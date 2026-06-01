package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func testOpts(filter ...bpf.Instruction) filterOpts {
	return filterOpts{
		perfPerCPUBuffer: 8192,
		actions:          []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx},
		filter:           filter,
	}
}

func matchByte(offset, val uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: offset, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
}

// bpfTempPath returns a unique path under /sys/fs/bpf suitable for bpffs operations.
// bpffs names may only contain [a-zA-Z0-9_-]; other characters are replaced with '_'.
func bpfTempPath(t *testing.T) string {
	t.Helper()
	name := t.Name()
	sanitized := make([]byte, len(name))
	for i, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			sanitized[i] = c
		default:
			sanitized[i] = '_'
		}
	}
	path := fmt.Sprintf("/sys/fs/bpf/xdpcap_%d_%s", os.Getpid(), sanitized)
	t.Cleanup(func() {
		os.RemoveAll(bpffsDir(path))
		os.RemoveAll(stateDir(path))
	})
	return path
}

func TestMain(m *testing.M) {
	err := unlimitLockedMemory()
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestMissingFilter(t *testing.T) {
	_, err := newFilterWithMap(hookMap(t, 1), bpfTempPath(t), testOpts())
	if err == nil {
		t.Fatal("empty filter accepted")
	}
}

func TestFilterProgramForAllModes(t *testing.T) {
	testFunc := func(xdpFragsEnabled bool) func(t *testing.T) {
		return func(t *testing.T) {
			hookMapSpec := internal.HookMapSpec.Copy()
			hookMapSpec.Name = "test_mode_hook_map"
			hookMap, err := ebpf.NewMap(hookMapSpec)
			if err != nil {
				t.Fatal(err)
			}

			entrrypointSpec := &ebpf.ProgramSpec{
				Type: ebpf.XDP,
				Instructions: asm.Instructions{
					// Context is already in R1.
					asm.LoadMapPtr(asm.R2, hookMap.FD()),
					asm.Mov.Imm(asm.R3, int32(xdpPass)),
					asm.FnTailCall.Call(),
					asm.Mov.Imm(asm.R0, int32(xdpPass)),
					asm.Return(),
				},
			}

			if xdpFragsEnabled {
				entrrypointSpec.Flags = unix.BPF_F_XDP_HAS_FRAGS
			}

			entrypoint, err := ebpf.NewProgram(entrrypointSpec)
			if err != nil {
				t.Fatal(err)
			}

			_, err = entrypoint.Run(&ebpf.RunOptions{
				Data: make([]byte, 14), // minimum Ethernet frame length required by XDP test runner
			})
			if err != nil {
				t.Fatal(err)
			}
			defer entrypoint.Close()

			opts := testOpts(bpf.RetConstant{Val: 0})
			opts.actions = []xdpAction{xdpPass}
			filter, err := newFilterWithMap(hookMap, bpfTempPath(t), opts)
			if err != nil {
				t.Fatal(err)
			}
			filter.close()
		}
	}

	t.Run("linear_buffer", testFunc(false))
	t.Run("xdp_frags", testFunc(true))
}

func TestUnknownAction(t *testing.T) {
	// progs with actions from 0-9. Only 0-3 are used currently.
	opts := testOpts(bpf.RetConstant{Val: 0})
	opts.actions = []xdpAction{}
	for i := 0; i < 10; i++ {
		opts.actions = append(opts.actions, xdpAction(i))
	}

	filter := mustNew(t, opts)
	defer filter.close()

	checkActions(t, opts.actions, filter, []byte{})
}

func TestAllActions(t *testing.T) {
	opts := testOpts(bpf.RetConstant{Val: 3})
	opts.actions = []xdpAction{}

	// progs with actions from 0-9. Only 0-3 are used currently.
	filter, err := newFilterWithMap(hookMap(t, 10), bpfTempPath(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.close()

	// check all actually used all the slots of the map
	if len(filter.actions) != 10 {
		t.Fatal("xdpAll unexpected number of actions:", len(filter.actions))
	}
	for i := 0; i < 10; i++ {
		if filter.actions[i] != xdpAction(i) {
			t.Fatalf("expected action %v, got %v", xdpAction(i), filter.actions[i])
		}
	}

	// We've already checked that filter.actions is what we expect
	checkActions(t, filter.actions, filter, []byte{})
}

func TestMetrics(t *testing.T) {
	opts := testOpts(matchByte(0, 2)...)
	filter := mustNew(t, opts)
	defer filter.close()

	// Match - 1 packet received, 1 matched
	checkActions(t, opts.actions, filter, []byte{2})

	metrics, err := filter.metrics()
	if err != nil {
		t.Fatal(err)
	}
	for action, progMetrics := range metrics {
		if progMetrics.receivedPackets != 1 {
			t.Fatalf("filter %v receivedPackets expected 1, got %d", action, progMetrics.receivedPackets)
		}

		if progMetrics.matchedPackets != 1 {
			t.Fatalf("filter %v matchedPackets expected 1, got %d", action, progMetrics.matchedPackets)
		}

		if progMetrics.perfOutputErrors != 0 {
			t.Fatalf("filter %v perfOutputErrors expected 0, got %d", action, progMetrics.perfOutputErrors)
		}
	}

	// No match - 2 packet received, 1 matched
	checkActions(t, opts.actions, filter, []byte{3})

	metrics, err = filter.metrics()
	if err != nil {
		t.Fatal(err)
	}
	for action, progMetrics := range metrics {
		if progMetrics.receivedPackets != 2 {
			t.Fatalf("filter %v receivedPackets expected 2, got %d", action, progMetrics.receivedPackets)
		}

		if progMetrics.matchedPackets != 1 {
			t.Fatalf("filter %v matchedPackets expected 1, got %d", action, progMetrics.matchedPackets)
		}

		if progMetrics.perfOutputErrors != 0 {
			t.Fatalf("filter %v perfOutputErrors expected 0, got %d", action, progMetrics.perfOutputErrors)
		}
	}
}

func TestPerf(t *testing.T) {
	opts := testOpts(matchByte(0, 0xde)...)
	filter := mustNew(t, opts)
	defer filter.close()

	// Match
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}

	for _, action := range opts.actions {
		checkAction(t, action, filter, pktData)

		pkt, err := filter.read()
		if err != nil {
			t.Errorf("action %v: %s", action, err)
			continue
		}

		if len(pkt.data) < len(pktData) {
			t.Errorf("action %v: unexpected packet length", action)
			continue
		}

		if !bytes.Equal(pktData, pkt.data[:len(pktData)]) {
			t.Errorf("action %v: unexpected packet contents", action)
			continue
		}
	}
}

func TestClose(t *testing.T) {
	opts := testOpts(matchByte(0, 2)...)
	filter := mustNew(t, opts)

	if err := filter.close(); err != nil {
		t.Fatalf("Error closing filter: %v", err)
	}

	_, err := filter.read()
	if err != errFilterClosed {
		t.Fatalf("closed filter read")
	}
}

// TestMultipleSubscribers verifies that two concurrent subscribers on the same hook each
// receive packets that match their individual filters. f2's coordinator program includes
// both subscribers, so running it fans packets to both perf buffers.
func TestMultipleSubscribers(t *testing.T) {
	hm := hookMap(t, len(testOpts().actions))
	hookPath := bpfTempPath(t)

	// f1 matches all packets.
	f1, err := newFilterWithMap(hm, hookPath, testOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatal(err)
	}
	defer f1.close()

	// f2 matches only packets whose first byte is 0xde.
	f2, err := newFilterWithMap(hm, hookPath, testOpts(matchByte(0, 0xde)...))
	if err != nil {
		t.Fatal(err)
	}
	defer f2.close()

	action := xdpPass
	matchingPkt := []byte{0xde, 0xad, 0xbe, 0xef}
	nonMatchingPkt := []byte{0x00, 0x00, 0x00, 0x00}

	// Run the coordinator from f2's view (includes both subscribers).
	// A packet matching both filters should reach both perf buffers.
	checkAction(t, action, f2, matchingPkt)

	pkt, err := f1.read()
	if err != nil {
		t.Fatalf("f1 read after matching packet: %v", err)
	}
	if len(pkt.data) < len(matchingPkt) || !bytes.Equal(pkt.data[:len(matchingPkt)], matchingPkt) {
		t.Fatalf("f1: unexpected packet data %v", pkt.data)
	}

	pkt, err = f2.read()
	if err != nil {
		t.Fatalf("f2 read after matching packet: %v", err)
	}
	if len(pkt.data) < len(matchingPkt) || !bytes.Equal(pkt.data[:len(matchingPkt)], matchingPkt) {
		t.Fatalf("f2: unexpected packet data %v", pkt.data)
	}

	// A packet that fails f2's filter should reach f1 (match-all) but not f2.
	checkAction(t, action, f2, nonMatchingPkt)

	if _, err = f1.read(); err != nil {
		t.Fatalf("f1 read after non-matching packet: %v", err)
	}

	// After two coordinator runs, f2 should have seen 2 received packets but only 1 matched.
	m, err := f2.metrics()
	if err != nil {
		t.Fatal(err)
	}
	if m[action].receivedPackets != 2 {
		t.Fatalf("f2 expected 2 received packets, got %d", m[action].receivedPackets)
	}
	if m[action].matchedPackets != 1 {
		t.Fatalf("f2 expected 1 matched packet, got %d", m[action].matchedPackets)
	}
}

// TestSubscriberUnregisterReinstalls verifies that when one subscriber closes,
// the coordinator is rebuilt to serve only the remaining subscribers.
func TestSubscriberUnregisterReinstalls(t *testing.T) {
	hm := hookMap(t, len(testOpts().actions))
	hookPath := bpfTempPath(t)

	// f1 matches all packets.
	f1, err := newFilterWithMap(hm, hookPath, testOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatal(err)
	}

	// f2 matches packets whose first byte is 0xde.
	f2, err := newFilterWithMap(hm, hookPath, testOpts(matchByte(0, 0xde)...))
	if err != nil {
		t.Fatal(err)
	}
	defer f2.close()

	// Close f1; the coordinator should be regenerated with f2 only.
	if err := f1.close(); err != nil {
		t.Fatalf("f1 close: %v", err)
	}

	// Register f3 so we get a fresh coordinator that reflects the updated list (f2 + f3).
	f3, err := newFilterWithMap(hm, hookPath, testOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatal(err)
	}
	defer f3.close()

	// Run a packet through f3's coordinator (f2 + f3 only — f1 is gone).
	action := xdpPass
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}
	checkAction(t, action, f3, pktData)

	pkt, err := f2.read()
	if err != nil {
		t.Fatalf("f2 read: %v", err)
	}
	if len(pkt.data) < len(pktData) || !bytes.Equal(pkt.data[:len(pktData)], pktData) {
		t.Fatalf("f2: unexpected packet data %v", pkt.data)
	}

	pkt, err = f3.read()
	if err != nil {
		t.Fatalf("f3 read: %v", err)
	}
	if len(pkt.data) < len(pktData) || !bytes.Equal(pkt.data[:len(pktData)], pktData) {
		t.Fatalf("f3: unexpected packet data %v", pkt.data)
	}
}

// TestPartialRegistrationReclaimed verifies that a slot whose PID file was written
// by the current process but whose filter/perf files were never created (simulating
// a crash mid-registration) is treated as stale and reclaimed by the next subscriber.
func TestPartialRegistrationReclaimed(t *testing.T) {
	hm := hookMap(t, 4)
	hp := bpfTempPath(t)

	// Pre-create state dir and write a PID file for slot 0 (our own PID),
	// but do NOT write the filter file or pin any maps.
	sd := stateDir(hp)
	if err := os.MkdirAll(sd, 0700); err != nil {
		t.Fatal(err)
	}
	pidFile := subPIDPath(hp, 0)
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		t.Fatal(err)
	}

	// A new subscriber must succeed by reclaiming the incomplete slot.
	opts := testOpts(bpf.RetConstant{Val: 3})
	opts.actions = []xdpAction{xdpPass}
	f, err := newFilterWithMap(hm, hp, opts)
	if err != nil {
		t.Fatalf("new subscriber rejected despite stale partial slot: %v", err)
	}
	f.close()
}

// TestStateDirInjective verifies that hook paths differing only by '.' vs '_'
// (or other previously-colliding characters) produce distinct state dirs.
func TestStateDirInjective(t *testing.T) {
	cases := [][2]string{
		{"/sys/fs/bpf/hook_test", "/sys/fs/bpf/hook.test"},
		{"/sys/fs/bpf/a_b", "/sys/fs/bpf/a.b"},
		{"/sys/fs/bpf/x__y", "/sys/fs/bpf/x_y"},
	}
	for _, pair := range cases {
		a, b := stateDir(pair[0]), stateDir(pair[1])
		if a == b {
			t.Errorf("stateDir collision: %q and %q both → %q", pair[0], pair[1], a)
		}
	}
}

// TestCloseRemovesAllHookMapEntries verifies that when the last subscriber closes,
// coordinator entries for all actions (including those the last subscriber never
// watched) are removed from the hook map.
func TestCloseRemovesAllHookMapEntries(t *testing.T) {
	hm := hookMap(t, 4)
	hp := bpfTempPath(t)

	// f1 subscribes to all four actions.
	opts1 := testOpts(bpf.RetConstant{Val: 3})
	opts1.actions = []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx}
	f1, err := newFilterWithMap(hm, hp, opts1)
	if err != nil {
		t.Fatal("f1:", err)
	}

	// f2 subscribes to PASS only.
	opts2 := testOpts(bpf.RetConstant{Val: 3})
	opts2.actions = []xdpAction{xdpPass}
	f2, err := newFilterWithMap(hm, hp, opts2)
	if err != nil {
		t.Fatal("f2:", err)
	}

	// Close f1 first, then f2 (the one with fewer actions).
	if err := f1.close(); err != nil {
		t.Fatal("f1 close:", err)
	}
	if err := f2.close(); err != nil {
		t.Fatal("f2 close:", err)
	}

	// Hook map must have no remaining entries.
	for _, a := range []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx} {
		var fd int32
		if err := hm.Lookup(int32(a), &fd); err == nil {
			t.Errorf("stale coordinator entry for action %v (fd %d) after all subscribers closed", a, fd)
		}
	}
}

// checkActions checks that all coordinator programs return their expected action.
func checkActions(t *testing.T, actions []xdpAction, f *filter, in []byte) {
	t.Helper()

	if len(actions) != len(f.programs) {
		t.Fatalf("mismatched number of actions (%d) and programs (%d)", len(actions), len(f.programs))
	}

	for _, action := range actions {
		checkAction(t, action, f, in)
	}
}

func checkAction(t *testing.T, action xdpAction, f *filter, in []byte) {
	t.Helper()

	if len(in) < 14 {
		padded := make([]byte, 14)
		copy(padded, in)
		in = padded
	}

	prog, ok := f.programs[action]
	if !ok {
		t.Fatalf("filter missing program for action %v", action)
	}

	ret, out, err := prog.program.Test(in)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(in, out) {
		t.Fatalf("Program modified input:\nIn: %v\nOut: %v\n", in, out)
	}

	retAction := xdpAction(ret)
	if retAction != action {
		t.Fatalf("Program returned %v, expected %v\n", retAction, action)
	}

	m, err := prog.metrics()
	if err != nil {
		t.Fatal("Can't retrieve metrics:", err)
	}

	if m.perfOutputErrors > 0 {
		t.Fatal("Couldn't write packet")
	}
}

func hookMap(t *testing.T, entries int) *ebpf.Map {
	t.Helper()

	spec := internal.HookMapSpec.Copy()
	spec.MaxEntries = uint32(entries)
	hookMap, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hookMap.Close() })

	return hookMap
}

func mustNew(t *testing.T, opts filterOpts) *filter {
	t.Helper()

	filter, err := newFilterWithMap(hookMap(t, len(opts.actions)), bpfTempPath(t), opts)
	if err != nil {
		t.Fatal(err)
	}

	return filter
}
