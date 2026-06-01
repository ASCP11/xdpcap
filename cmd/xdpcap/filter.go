package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

type packet struct {
	action xdpAction
	data   []byte
}

var perfMapSpec = ebpf.MapSpec{
	Name: "xdpcap_perf",
	Type: ebpf.PerfEventArray,
}

type filterOpts struct {
	perfPerCPUBuffer int
	perfWatermark    int

	// Requested actions. If empty or nil, all actions exposed by hookMap are used.
	actions []xdpAction
	filter  []bpf.Instruction
}

// filter represents a single capture subscriber.
type filter struct {
	hookMap      *ebpf.Map
	hookPath     string // bpffs path of the hook map
	ownsHookMap  bool   // true when hookMap was opened by newFilter and must be closed by close()
	slot         int
	reader       *perf.Reader
	perfMap      *ebpf.Map
	programs     map[xdpAction]*program // coordinator progs + this subscriber's metrics maps
	actions      []xdpAction
	xdpFrags     bool
	xdpAttach    bool
}

// newFilter creates a filter from a pinned hook map path.
func newFilter(hookMapPath string, opts filterOpts) (*filter, error) {
	hookMap, err := ebpf.LoadPinnedMap(hookMapPath, nil)
	if err != nil {
		return nil, errors.Wrap(err, "loading hook map")
	}

	f, err := newFilterWithMap(hookMap, hookMapPath, opts)
	if err != nil {
		hookMap.Close()
		return nil, err
	}
	f.ownsHookMap = true
	return f, nil
}

// newFilterWithMap creates a filter from an already-opened hook map.
// hookPath is the bpffs path used for multi-subscriber state; if empty,
// the subscriber directory will be created under /sys/fs/bpf using the map's
// name and current PID (suitable for testing).
func newFilterWithMap(hookMap *ebpf.Map, hookPath string, opts filterOpts) (*filter, error) {
	if len(opts.filter) == 0 {
		return nil, errors.New("at least one filter cBPF instruction required")
	}

	if err := internal.CheckHookMap(hookMap); err != nil {
		return nil, errors.Wrap(err, "invalid hook map ABI")
	}

	// Derive a bpffs working path when the caller doesn't provide one.
	// Use time.Now().UnixNano() rather than hookMap.FD() because OS file descriptors
	// are reused after close, which would collide if a new map gets the same FD number.
	if hookPath == "" {
		hookPath = fmt.Sprintf("/sys/fs/bpf/xdpcap_%d_%d", os.Getpid(), time.Now().UnixNano())
	}

	// Determine which actions to capture.
	actions := opts.actions
	if len(actions) == 0 {
		actions = allActions(hookMap)
	}

	// Create this subscriber's perf map and metrics maps.
	perfMap, err := ebpf.NewMap(&perfMapSpec)
	if err != nil {
		return nil, errors.Wrap(err, "creating perf map")
	}

	metricsMaps := make(map[xdpAction]*ebpf.Map, len(actions))
	for _, a := range actions {
		spec := metricsSpec
		m, err := ebpf.NewMap(&spec)
		if err != nil {
			perfMap.Close()
			for _, already := range metricsMaps {
				already.Close()
			}
			return nil, errors.Wrapf(err, "creating metrics map for action %v", a)
		}
		metricsMaps[a] = m
	}

	reader, err := perf.NewReaderWithOptions(perfMap, opts.perfPerCPUBuffer, perf.ReaderOptions{
		Watermark: opts.perfWatermark,
	})
	if err != nil {
		perfMap.Close()
		for _, m := range metricsMaps {
			m.Close()
		}
		return nil, errors.Wrap(err, "creating perf reader")
	}

	f := &filter{
		hookMap:  hookMap,
		hookPath: hookPath,
		slot:     -1,
		reader:   reader,
		perfMap:  perfMap,
		actions:  actions,
	}

	// Register subscriber and install/regenerate coordinator under lock.
	var coordProgs map[xdpAction]*ebpf.Program
	var xdpFrags, xdpAttach bool

	err = withSubsLock(hookPath, func() error {
		// Purge stale entries and load current subscriber list.
		existing, err := loadAllSubscribers(hookPath)
		if err != nil {
			return errors.Wrap(err, "loading existing subscribers")
		}
		defer func() {
			for _, s := range existing {
				s.close()
			}
		}()

		// Claim a slot.
		slot, err := registerSubscriber(hookPath, opts.filter, perfMap, metricsMaps)
		if err != nil {
			return err
		}
		f.slot = slot

		// Build the full subscriber list without a second bpffs walk: append a
		// loadedSub for this subscriber using the already-open in-memory maps.
		// Note: this subscriber's maps are owned by f and must NOT be closed here;
		// only the incumbents in existing are closed by the deferred loop above.
		selfSub := loadedSub{slot: slot, filter: opts.filter, perfMap: perfMap, metricsMaps: metricsMaps}
		allSubs := append(existing, selfSub)

		if len(existing) == 0 {
			// First subscriber: install coordinator fresh (with fallback probe).
			var frags, attach bool
			coordProgs, frags, attach, err = installCoordinator(hookMap, allSubs, actions)
			if err != nil {
				cleanupSlot(hookPath, slot)
				f.slot = -1
				return errors.Wrap(err, "installing coordinator")
			}
			xdpFrags, xdpAttach = frags, attach
		} else {
			// Subsequent subscriber: reuse the previously probed frags/attach mode.
			frags, attach, modeErr := readCoordinatorMode(hookPath)
			if modeErr != nil {
				// Mode file absent or unreadable (e.g. first subscriber crashed before
				// writeCoordinatorMode). Re-probe with the full fallback sequence to avoid
				// producing a partial hook-map update from wrong flags.
				var instErr error
				coordProgs, frags, attach, instErr = installCoordinator(hookMap, allSubs, actions)
				if instErr != nil {
					cleanupSlot(hookPath, slot)
					f.slot = -1
					return errors.Wrap(instErr, "installing coordinator for subsequent subscriber (mode file missing)")
				}
			} else {
				var reinstErr error
				coordProgs, reinstErr = reinstallCoordinator(hookMap, allSubs, actions, frags, attach)
				if reinstErr != nil {
					cleanupSlot(hookPath, slot)
					f.slot = -1
					return errors.Wrap(reinstErr, "reinstalling coordinator")
				}
			}
			xdpFrags, xdpAttach = frags, attach
		}

		// Persist the mode so future subscribers can reuse it.
		if err := writeCoordinatorMode(hookPath, xdpFrags, xdpAttach); err != nil {
			// Non-fatal; next subscriber will re-probe on EINVAL.
			fmt.Fprintf(os.Stderr, "xdpcap: warning: could not persist coordinator mode: %v\n", err)
		}

		return nil
	})
	if err != nil {
		reader.Close()
		perfMap.Close()
		for _, m := range metricsMaps {
			m.Close()
		}
		return nil, err
	}

	f.xdpFrags = xdpFrags
	f.xdpAttach = xdpAttach

	// Build the programs map: coordinator program + this subscriber's metrics.
	f.programs = make(map[xdpAction]*program, len(actions))
	for _, action := range actions {
		f.programs[action] = &program{
			program:    coordProgs[action],
			metricsMap: metricsMaps[action],
		}
	}

	return f, nil
}

// allActions returns every action exposed by the map.
func allActions(hookMap *ebpf.Map) []xdpAction {
	var actions []xdpAction
	for i := 0; i < int(hookMap.MaxEntries()); i++ {
		actions = append(actions, xdpAction(i))
	}
	return actions
}

// close detaches this subscriber, regenerates (or removes) the coordinator, and
// releases all resources.
func (f *filter) close() error {
	var lastErr error

	f.reader.Close()

	if f.slot >= 0 {
		err := withSubsLock(f.hookPath, func() error {
			// Remove our slot files first.
			cleanupSlot(f.hookPath, f.slot)

			// Reload remaining subscribers.
			remaining, err := loadAllSubscribers(f.hookPath)
			if err != nil {
				return errors.Wrap(err, "loading remaining subscribers")
			}
			defer func() {
				for _, s := range remaining {
					s.close()
				}
			}()

			if len(remaining) == 0 {
				// Sweep the entire hook map, not just f.actions: other subscribers
				// may have installed coordinators for actions this subscriber never
				// watched, and those pass-throughs must also be cleaned up.
				if err := removeCoordinator(f.hookMap, allActions(f.hookMap)); err != nil {
					return err
				}
				os.Remove(coordinatorModePath(f.hookPath))
				return nil
			}

			newProgs, err := reinstallCoordinator(f.hookMap, remaining, f.actions, f.xdpFrags, f.xdpAttach)
			// Close the returned program FDs: the kernel holds its own references via
			// the hook map; userspace no longer needs them after the Put calls succeed.
			for _, p := range newProgs {
				p.Close()
			}
			return errors.Wrap(err, "reinstalling coordinator after unsubscribe")
		})
		if err != nil {
			lastErr = err
		}
	}

	// Close coordinator programs and metrics maps owned by this subscriber.
	// cleanupSlot removed the bpffs pin files; these Close() calls release the
	// userspace FDs.
	for _, prog := range f.programs {
		prog.program.Close()
		prog.metricsMap.Close()
	}

	f.perfMap.Close()

	// Close the hook map only when we opened it (newFilter path). When the caller
	// opened it and passed it to newFilterWithMap, they retain ownership.
	if f.ownsHookMap {
		f.hookMap.Close()
	}

	return lastErr
}

var errFilterClosed = errors.New("filter closed")

func (f *filter) read() (packet, error) {
	record, err := f.reader.Read()
	switch {
	case errors.Is(err, perf.ErrClosed):
		return packet{}, errFilterClosed
	case err != nil:
		return packet{}, err
	}

	if record.LostSamples > 0 {
		return packet{}, errors.Errorf("lost %d packets", record.LostSamples)
	}

	raw := record.RawSample
	if len(raw) < 16 {
		return packet{}, errors.New("perf packet data < 16 bytes")
	}

	action := xdpAction(nativeEndian.Uint64(raw[:8]))
	length := int(nativeEndian.Uint64(raw[8:16]))
	data := raw[16:]

	if len(data) < length {
		return packet{}, errors.New("perf packet truncated")
	}

	return packet{action: action, data: data[:length]}, nil
}

func (f *filter) metrics() (map[xdpAction]metrics, error) {
	result := make(map[xdpAction]metrics, len(f.programs))
	for action, prog := range f.programs {
		m, err := prog.metrics()
		if err != nil {
			return nil, errors.Wrapf(err, "metrics for action %v", action)
		}
		result[action] = m
	}
	return result, nil
}

// ---- coordinator mode persistence ----

func coordinatorModePath(hookPath string) string {
	return filepath.Join(stateDir(hookPath), "coord_mode")
}

func writeCoordinatorMode(hookPath string, frags, attachType bool) error {
	val := 0
	if frags {
		val |= 1
	}
	if attachType {
		val |= 2
	}
	return os.WriteFile(coordinatorModePath(hookPath), []byte(fmt.Sprintf("%d", val)), 0644)
}

func readCoordinatorMode(hookPath string) (frags bool, attachType bool, err error) {
	data, err := os.ReadFile(coordinatorModePath(hookPath))
	if err != nil {
		return false, false, err
	}
	var n int
	if _, err := fmt.Sscanf(string(data), "%d", &n); err != nil {
		return false, false, errors.Wrap(err, "parsing coordinator mode")
	}
	return n&1 != 0, n&2 != 0, nil
}
