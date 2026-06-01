package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// maxSubscribers is the compile-time cap on concurrent xdpcap captures per hook.
const maxSubscribers = 16

// stackReserved is the number of stack bytes the coordinator uses before cbpfc scratch:
//   [R10-4]      4-byte map key
//   [R10-8..23]  16-byte perf output header (u64 action, u64 length)
//                 R10-16: action (sent first → raw[0:8] in perf record)
//                 R10-8:  length (sent second → raw[8:16] in perf record)
const stackReserved = 20

const BPF_F_CURRENT_CPU int64 = 0xFFFFFFFF

// ---- metrics types (moved here from program.go) ----

type rawMetrics [3]uint64
type rawMetric int

const (
	receivedPackets  rawMetric = iota // index 0
	matchedPackets                    // index 1
	perfOutputErrors                  // index 2
)

type metrics struct {
	receivedPackets  uint64
	matchedPackets   uint64
	perfOutputErrors uint64
}

var metricsSpec = ebpf.MapSpec{
	Name:       "xdpcap_metrics",
	Type:       ebpf.PerCPUArray,
	KeySize:    4,
	ValueSize:  uint32(len(rawMetrics{}) * 8),
	MaxEntries: 1,
}

// ---- program type (coordinator program + per-subscriber metrics map) ----

// program wraps a coordinator BPF program and one subscriber's metrics map for that action.
type program struct {
	program    *ebpf.Program
	metricsMap *ebpf.Map
}

func (p *program) close() {
	p.metricsMap.Close()
	p.program.Close()
}

func (p *program) metrics() (metrics, error) {
	var perCPU []rawMetrics
	if err := p.metricsMap.Lookup(uint32(0), &perCPU); err != nil {
		return metrics{}, errors.Wrap(err, "accessing metrics map")
	}

	var m metrics
	for _, cpu := range perCPU {
		m.receivedPackets += cpu[receivedPackets]
		m.matchedPackets += cpu[matchedPackets]
		m.perfOutputErrors += cpu[perfOutputErrors]
	}
	return m, nil
}

// ---- bpffs state ----

// bpffsDir returns the bpffs directory used for pinned maps.
// bpffs only allows BPF object pins; regular files must live elsewhere.
func bpffsDir(hookPath string) string {
	return hookPath + "_subs"
}

// stateDir returns the regular-filesystem directory for PID, filter, and mode files.
// The encoding is injective: alphanumerics and '-' are kept verbatim, '_' is
// doubled to '__', and every other byte is encoded as '_HH' (lowercase hex).
// Operating byte-by-byte means any two distinct hookPaths produce distinct dirs.
func stateDir(hookPath string) string {
	var b strings.Builder
	for i := 0; i < len(hookPath); i++ {
		c := hookPath[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		case c == '_':
			b.WriteString("__")
		default:
			fmt.Fprintf(&b, "_%02x", c)
		}
	}
	return filepath.Join("/tmp", "xdpcap_"+b.String())
}

// subPerfPath is the bpffs pin path for a subscriber's perf map.
func subPerfPath(hookPath string, slot int) string {
	return filepath.Join(bpffsDir(hookPath), fmt.Sprintf("%d_perf", slot))
}

// subMetricsPath is the bpffs pin path for a subscriber's metrics map for one action.
func subMetricsPath(hookPath string, slot int, action xdpAction) string {
	return filepath.Join(bpffsDir(hookPath), fmt.Sprintf("%d_metrics_%d", slot, int(action)))
}

// subFilterPath is the regular-fs path for a subscriber's serialized cBPF filter.
func subFilterPath(hookPath string, slot int) string {
	return filepath.Join(stateDir(hookPath), fmt.Sprintf("%d_filter", slot))
}

// subPIDPath is the regular-fs path for a subscriber's PID file.
func subPIDPath(hookPath string, slot int) string {
	return filepath.Join(stateDir(hookPath), fmt.Sprintf("%d_pid", slot))
}

// withSubsLock runs fn under an exclusive flock on stateDir.
// Both stateDir and bpffsDir are created if absent.
func withSubsLock(hookPath string, fn func() error) error {
	sd := stateDir(hookPath)
	if err := os.MkdirAll(sd, 0700); err != nil {
		return errors.Wrap(err, "creating state dir")
	}
	if err := os.MkdirAll(bpffsDir(hookPath), 0700); err != nil {
		return errors.Wrap(err, "creating bpffs dir")
	}

	f, err := os.Open(sd)
	if err != nil {
		return errors.Wrap(err, "opening state dir for lock")
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return errors.Wrap(err, "acquiring subscriber lock")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck

	return fn()
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// cleanupSlot removes all state and bpffs files for a slot.
func cleanupSlot(hookPath string, slot int) {
	os.Remove(subFilterPath(hookPath, slot))
	os.Remove(subPIDPath(hookPath, slot))
	os.Remove(subPerfPath(hookPath, slot))
	// Remove metrics pins for all possible action indices, not just the standard 5,
	// to handle hooks with non-standard action counts.
	for a := xdpAction(0); a < xdpAction(32); a++ {
		os.Remove(subMetricsPath(hookPath, slot, a))
	}
}

// ---- filter serialization ----

func writeFilter(path string, filter []bpf.Instruction) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, insn := range filter {
		raw, err := insn.Assemble()
		if err != nil {
			return errors.Wrap(err, "assembling instruction")
		}
		if err := binary.Write(f, binary.LittleEndian, raw); err != nil {
			return err
		}
	}
	return nil
}

func readFilter(path string) ([]bpf.Instruction, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var insns []bpf.Instruction
	for {
		var raw bpf.RawInstruction
		err := binary.Read(f, binary.LittleEndian, &raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		insns = append(insns, raw.Disassemble())
	}
	return insns, nil
}

// ---- loaded subscriber ----

// loadedSub is a subscriber loaded from bpffs, used to regenerate the coordinator.
type loadedSub struct {
	slot        int
	filter      []bpf.Instruction
	perfMap     *ebpf.Map
	metricsMaps map[xdpAction]*ebpf.Map
}

func (s *loadedSub) close() {
	s.perfMap.Close()
	for _, m := range s.metricsMaps {
		m.Close()
	}
}

// registerSubscriber claims a free slot, writes state files, and pins maps to bpffs.
// The caller must hold the subsDir lock.
func registerSubscriber(
	hookPath string,
	filter []bpf.Instruction,
	perfMap *ebpf.Map,
	metricsMaps map[xdpAction]*ebpf.Map,
) (int, error) {
	// Scan for a free slot, cleaning up stale ones as we go.
	slot := -1
	for i := 0; i < maxSubscribers; i++ {
		data, err := os.ReadFile(subPIDPath(hookPath, i))
		if os.IsNotExist(err) {
			slot = i
			break
		}
		if err != nil {
			return 0, errors.Wrapf(err, "reading pid for slot %d", i)
		}
		pid, pidErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if pidErr != nil || pid <= 0 || !processAlive(pid) {
			cleanupSlot(hookPath, i)
			slot = i
			break
		}
	}
	if slot < 0 {
		return 0, errors.Errorf("all %d subscriber slots are occupied", maxSubscribers)
	}

	// Write PID first so we own the slot.
	if err := os.WriteFile(subPIDPath(hookPath, slot), []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		return 0, errors.Wrap(err, "writing pid file")
	}

	// Write filter.
	if err := writeFilter(subFilterPath(hookPath, slot), filter); err != nil {
		cleanupSlot(hookPath, slot)
		return 0, errors.Wrap(err, "writing filter file")
	}

	// Pin perf map.
	if err := perfMap.Pin(subPerfPath(hookPath, slot)); err != nil {
		cleanupSlot(hookPath, slot)
		return 0, errors.Wrap(err, "pinning perf map")
	}

	// Pin metrics maps (only for the actions this subscriber captures).
	for a, m := range metricsMaps {
		if err := m.Pin(subMetricsPath(hookPath, slot, a)); err != nil {
			cleanupSlot(hookPath, slot)
			return 0, errors.Wrapf(err, "pinning metrics map for action %v", a)
		}
	}

	return slot, nil
}

// loadAllSubscribers reads all live subscriber slots from bpffs.
// Stale entries (dead PID) are cleaned up. Caller must hold the subsDir lock.
// On error, any already-loaded subscribers are closed before returning.
func loadAllSubscribers(hookPath string) ([]loadedSub, error) {
	var subs []loadedSub

	closeAll := func() {
		for _, s := range subs {
			s.close()
		}
	}

	for i := 0; i < maxSubscribers; i++ {
		data, err := os.ReadFile(subPIDPath(hookPath, i))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			closeAll()
			return nil, errors.Wrapf(err, "reading pid for slot %d", i)
		}

		pid, pidErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if pidErr != nil || pid <= 0 || !processAlive(pid) {
			cleanupSlot(hookPath, i)
			continue
		}

		filter, err := readFilter(subFilterPath(hookPath, i))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// PID written but process crashed before completing registration.
				cleanupSlot(hookPath, i)
				continue
			}
			closeAll()
			return nil, errors.Wrapf(err, "loading filter for slot %d", i)
		}

		perfMap, err := ebpf.LoadPinnedMap(subPerfPath(hookPath, i), nil)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				cleanupSlot(hookPath, i)
				continue
			}
			closeAll()
			return nil, errors.Wrapf(err, "loading perf map for slot %d", i)
		}

		metricsMaps := make(map[xdpAction]*ebpf.Map)
		for a := xdpAction(0); a < xdpAction(32); a++ {
			path := subMetricsPath(hookPath, i, a)
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				continue // subscriber doesn't capture this action
			}
			m, err := ebpf.LoadPinnedMap(path, nil)
			if err != nil {
				perfMap.Close()
				for _, already := range metricsMaps {
					already.Close()
				}
				closeAll()
				return nil, errors.Wrapf(err, "loading metrics map for slot %d action %v", i, a)
			}
			metricsMaps[a] = m
		}

		subs = append(subs, loadedSub{
			slot:        i,
			filter:      filter,
			perfMap:     perfMap,
			metricsMaps: metricsMaps,
		})
	}

	return subs, nil
}

// ---- BPF coordinator program generation ----

// generateCoordinatorInsns builds the eBPF instruction stream for one coordinator program.
// The program fans packets out to every subscriber's filter+perf section, then returns action.
func generateCoordinatorInsns(subs []loadedSub, action xdpAction) (asm.Instructions, error) {
	// Only include subscribers that have a metrics map for this action.
	var activeSubs []loadedSub
	for _, s := range subs {
		if _, ok := s.metricsMaps[action]; ok {
			activeSubs = append(activeSubs, s)
		}
	}
	subs = activeSubs

	// If no subscribers are interested in this action, emit a minimal pass-through.
	if len(subs) == 0 {
		return asm.Instructions{
			asm.Mov.Imm(asm.R0, int32(action)),
			asm.Return(),
		}, nil
	}

	exitLabel := "coord_exit"

	subStartLabel := func(i int) string { return fmt.Sprintf("s%d_start", i) }
	subResultLabel := func(i int) string { return fmt.Sprintf("s%d_result", i) }
	nextOrExit := func(i int) string {
		if i < len(subs)-1 {
			return subStartLabel(i + 1)
		}
		return exitLabel
	}

	// Prologue: save ctx, compute pkt_len.
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),             // R6 = ctx (callee-saved)
		asm.LoadMem(asm.R1, asm.R6, 4, asm.Word), // R1 = ctx.data_end
		asm.LoadMem(asm.R0, asm.R6, 0, asm.Word), // R0 = ctx.data
		asm.Mov.Reg(asm.R8, asm.R1),              // R8 = pkt_len (callee-saved)
		asm.Sub.Reg(asm.R8, asm.R0),
	}

	for i, sub := range subs {
		metricsMap, ok := sub.metricsMaps[action]
		if !ok {
			return nil, errors.Errorf("subscriber %d missing metrics map for action %v", sub.slot, action)
		}
		next := nextOrExit(i)

		// Metrics map lookup.
		metricsSection := asm.Instructions{
			asm.LoadMapPtr(asm.R1, metricsMap.FD()).WithSymbol(subStartLabel(i)),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -4),
			asm.StoreImm(asm.R2, 0, 0, asm.Word),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, next), // null metrics → skip subscriber
			asm.Mov.Reg(asm.R7, asm.R0),  // R7 = metrics ptr (callee-saved)

			// Reload pkt_start / pkt_end (clobbered by map lookup helper).
			asm.LoadMem(asm.R0, asm.R6, 0, asm.Word),
			asm.LoadMem(asm.R1, asm.R6, 4, asm.Word),

			// receivedPackets++
			asm.LoadMem(asm.R2, asm.R7, int16(8*receivedPackets), asm.DWord),
			asm.Add.Imm(asm.R2, 1),
			asm.StoreMem(asm.R7, int16(8*receivedPackets), asm.R2, asm.DWord),
		}

		// cBPF → eBPF filter.
		filterInsns, err := cbpfc.ToEBPF(sub.filter, cbpfc.EBPFOpts{
			PacketStart: asm.R0,
			PacketEnd:   asm.R1,
			Result:      asm.R2,
			ResultLabel: subResultLabel(i),
			Working:     [4]asm.Register{asm.R2, asm.R3, asm.R4, asm.R5},
			StackOffset: stackReserved,
			LabelPrefix: fmt.Sprintf("s%d", i),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "compiling filter for subscriber slot %d", sub.slot)
		}

		// Post-filter: check result, increment counters, perf output.
		resultSection := asm.Instructions{
			// R2 == 0 → no match; jump to next subscriber (or exit).
			asm.JEq.Imm(asm.R2, 0, next).WithSymbol(subResultLabel(i)),

			// matchedPackets++
			asm.LoadMem(asm.R2, asm.R7, int16(8*matchedPackets), asm.DWord),
			asm.Add.Imm(asm.R2, 1),
			asm.StoreMem(asm.R7, int16(8*matchedPackets), asm.R2, asm.DWord),

			// bpf_perf_event_output(ctx, perf_map, flags, header_ptr, sizeof_header)
			asm.Mov.Reg(asm.R1, asm.R6),                        // ctx
			asm.LoadMapPtr(asm.R2, sub.perfMap.FD()),            // perf map
			asm.Mov.Reg(asm.R3, asm.R8),                        // pkt_len → flags
			asm.LSh.Imm(asm.R3, 32),
			asm.LoadImm(asm.R0, BPF_F_CURRENT_CPU, asm.DWord),
			asm.Or.Reg(asm.R3, asm.R0),
			// Build header: [R10-8] = length, [R10-16] = action.
			asm.Mov.Reg(asm.R4, asm.R10),
			asm.Add.Imm(asm.R4, -8),
			asm.StoreMem(asm.R4, 0, asm.R8, asm.DWord),
			asm.Add.Imm(asm.R4, -8),
			asm.StoreImm(asm.R4, 0, int64(action), asm.DWord),
			asm.Mov.Imm(asm.R5, 2*8),
			asm.FnPerfEventOutput.Call(),

			// Success: jump to next subscriber.
			asm.JEq.Imm(asm.R0, 0, next),

			// perfOutputErrors++
			asm.LoadMem(asm.R2, asm.R7, int16(8*perfOutputErrors), asm.DWord),
			asm.Add.Imm(asm.R2, 1),
			asm.StoreMem(asm.R7, int16(8*perfOutputErrors), asm.R2, asm.DWord),
			// Fall through to next subscriber (or exit).
		}

		insns = append(insns, metricsSection...)
		insns = append(insns, filterInsns...)
		insns = append(insns, resultSection...)
	}

	// Exit: return the XDP action this coordinator was installed for.
	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(action)).WithSymbol(exitLabel),
		asm.Return(),
	)

	return insns, nil
}

// buildCoordinatorPrograms generates and loads one coordinator *ebpf.Program per XDP action.
func buildCoordinatorPrograms(subs []loadedSub, actions []xdpAction, xdpFragsMode, xdpAttachType bool) (map[xdpAction]*ebpf.Program, error) {
	progs := make(map[xdpAction]*ebpf.Program, len(actions))

	for _, action := range actions {
		insns, err := generateCoordinatorInsns(subs, action)
		if err != nil {
			for _, p := range progs {
				p.Close()
			}
			return nil, errors.Wrapf(err, "generating coordinator for action %v", action)
		}

		spec := &ebpf.ProgramSpec{
			Name:         fmt.Sprintf("xdpcap_coord_%v", action),
			Type:         ebpf.XDP,
			Instructions: insns,
			License:      "GPL",
		}
		if xdpFragsMode {
			spec.Flags |= unix.BPF_F_XDP_HAS_FRAGS
		}
		if xdpAttachType {
			spec.AttachType = ebpf.AttachXDP
		}

		prog, err := ebpf.NewProgram(spec)
		if err != nil {
			for _, p := range progs {
				p.Close()
			}
			return nil, errors.Wrapf(err, "loading coordinator for action %v", action)
		}
		progs[action] = prog
	}

	return progs, nil
}

// installCoordinator installs coordinator programs into hookMap for the given actions.
// It probes for frags mode and attach-type support independently, mirroring the
// original per-program fallback strategy.
func installCoordinator(hookMap *ebpf.Map, subs []loadedSub, actions []xdpAction) (coordProgs map[xdpAction]*ebpf.Program, xdpFragsMode bool, xdpAttachType bool, err error) {
	tryInstall := func(frags, attachType bool) (map[xdpAction]*ebpf.Program, error) {
		progs, buildErr := buildCoordinatorPrograms(subs, actions, frags, attachType)
		if buildErr != nil {
			return nil, buildErr
		}
		for _, action := range actions {
			if e := hookMap.Put(int32(action), int32(progs[action].FD())); e != nil {
				for _, p := range progs {
					p.Close()
				}
				return nil, errors.Wrapf(e, "installing coordinator for action %v", action)
			}
		}
		return progs, nil
	}

	// Attempt 1: no special modes.
	progs, err1 := tryInstall(false, false)
	if err1 == nil {
		return progs, false, false, nil
	}
	if !errors.Is(err1, unix.EINVAL) {
		return nil, false, false, err1
	}

	// Attempt 2: XDP frags mode (required when hook map owner program uses frags).
	progs, err2 := tryInstall(true, false)
	if err2 == nil {
		fmt.Fprintf(os.Stderr, "attaching coordinator in XDP frags mode\n")
		return progs, true, false, nil
	}
	if !errors.Is(err2, unix.EINVAL) {
		return nil, false, false, err2
	}

	// Attempt 3: frags + expected attach type (required on kernels ≥ 6.1).
	progs, err3 := tryInstall(true, true)
	if err3 == nil {
		fmt.Fprintf(os.Stderr, "attaching coordinator in XDP frags mode with explicit attach type\n")
		return progs, true, true, nil
	}
	if !errors.Is(err3, unix.EINVAL) {
		return nil, false, false, err3
	}

	// Attempt 4: attach type only, no frags.
	progs, err4 := tryInstall(false, true)
	if err4 == nil {
		return progs, false, true, nil
	}

	return nil, false, false, err1
}

// reinstallCoordinator regenerates the coordinator after subscriber list changes.
// Existing programs are replaced atomically (one Put per action).
func reinstallCoordinator(hookMap *ebpf.Map, subs []loadedSub, actions []xdpAction, xdpFragsMode, xdpAttachType bool) (map[xdpAction]*ebpf.Program, error) {
	progs, err := buildCoordinatorPrograms(subs, actions, xdpFragsMode, xdpAttachType)
	if err != nil {
		return nil, err
	}
	for _, action := range actions {
		if e := hookMap.Put(int32(action), int32(progs[action].FD())); e != nil {
			for _, p := range progs {
				p.Close()
			}
			return nil, errors.Wrapf(e, "reinstalling coordinator for action %v", action)
		}
	}
	return progs, nil
}

// removeCoordinator deletes coordinator entries from hookMap.
// Missing entries (never installed for a given action) are silently skipped.
// Returns the first non-ENOENT error encountered; remaining actions are still attempted.
func removeCoordinator(hookMap *ebpf.Map, actions []xdpAction) error {
	var firstErr error
	for _, action := range actions {
		if err := hookMap.Delete(int32(action)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			if firstErr == nil {
				firstErr = errors.Wrapf(err, "removing coordinator for action %v", action)
			}
		}
	}
	return firstErr
}
