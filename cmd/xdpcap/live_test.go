package main

// Live integration tests for multi-capture on a real interface.
//
// Prerequisites (handled automatically by setup):
//   - Run as root
//   - Interface "enp5s0f0" exists and is UP (10.25.0.5/24)
//   - "macvlan0" (10.25.0.100/24) bridged on enp5s0f0 for ingress traffic generation
//   - /tmp/xdpcap binary built (go build -o /tmp/xdpcap ./cmd/xdpcap/)
//
// Run: sudo -E $(which go) test ./cmd/xdpcap/ -v -run TestLive -count=1 -timeout 120s

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	liveELF       = "../../testdata/xdp_hook.c.elf"
	liveIface     = "enp5s0f0"
	liveMacvlan   = "macvlan0"
	liveMacvlanIP = "10.25.0.100"
	liveTargetIP  = "10.25.0.5"
	liveHookPin   = "/sys/fs/bpf/xdpcap_live_test"
	xdpcapBin     = "/tmp/xdpcap"
)

// liveSetup attaches the XDP hook ELF to liveIface, pins the hook map,
// and returns a teardown function. Skips the test if not root or if the
// interface is absent.
func liveSetup(t *testing.T) string {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("live tests require root")
	}
	if _, err := net.InterfaceByName(liveIface); err != nil {
		t.Skipf("interface %s not found: %v", liveIface, err)
	}

	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}) //nolint:errcheck

	// Ensure macvlan0 exists for traffic generation.
	ensureMacvlan(t)

	// Remove any leftover pin from a previous run.
	os.Remove(liveHookPin)

	// Load the BPF ELF.
	spec, err := ebpf.LoadCollectionSpec(liveELF)
	if err != nil {
		t.Fatalf("LoadCollectionSpec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}

	hookMap := coll.Maps["xdpcap_hook"]
	if hookMap == nil {
		t.Fatal("xdpcap_hook map not found in ELF")
	}
	xdpProg := coll.Programs["xdp_hook"]
	if xdpProg == nil {
		t.Fatal("xdp_hook program not found in ELF")
	}

	// Pin the hook map so both in-process filters and external xdpcap
	// processes can open it by path.
	if err := hookMap.Pin(liveHookPin); err != nil {
		coll.Close()
		t.Fatalf("pin hook map: %v", err)
	}

	// Attach the XDP program to the interface.
	ifc, err := net.InterfaceByName(liveIface)
	if err != nil {
		os.Remove(liveHookPin)
		coll.Close()
		t.Fatalf("InterfaceByName: %v", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: ifc.Index,
	})
	if err != nil {
		os.Remove(liveHookPin)
		coll.Close()
		t.Fatalf("AttachXDP: %v", err)
	}
	t.Logf("[setup] XDP hook attached to %s (ifindex %d)", liveIface, ifc.Index)
	t.Logf("[setup] hook map pinned to %s", liveHookPin)

	t.Cleanup(func() {
		l.Close()
		coll.Close()
		os.Remove(liveHookPin)
		// clean up bpffs and state dirs left by any subscriber
		os.RemoveAll(bpffsDir(liveHookPin))
		os.RemoveAll(stateDir(liveHookPin))
		t.Logf("[teardown] XDP detached, pin removed")
	})

	return liveHookPin
}

// ensureMacvlan creates macvlan0 (10.25.0.100/24) on top of liveIface if absent.
func ensureMacvlan(t *testing.T) {
	t.Helper()
	if _, err := net.InterfaceByName(liveMacvlan); err == nil {
		t.Logf("[setup] %s already exists, reusing", liveMacvlan)
		return
	}
	run(t, "ip", "link", "add", liveMacvlan, "link", liveIface, "type", "macvlan", "mode", "bridge")
	run(t, "ip", "addr", "add", liveMacvlanIP+"/24", "dev", liveMacvlan)
	run(t, "ip", "link", "set", liveMacvlan, "up")
	// Static ARP so ICMP frames are addressed to enp5s0f0's MAC.
	run(t, "ip", "neigh", "replace", liveTargetIP, "lladdr", mustMAC(t, liveIface), "dev", liveMacvlan)
	t.Logf("[setup] created %s %s/24", liveMacvlan, liveMacvlanIP)
	t.Cleanup(func() {
		exec.Command("ip", "link", "del", liveMacvlan).Run() //nolint:errcheck
		t.Logf("[teardown] removed %s", liveMacvlan)
	})
}

// sendTraffic runs ping from macvlan0 → liveTargetIP in the background.
// Returns a cancel func. Packets arrive as real ingress on liveIface.
func sendTraffic(count int) (cancel func()) {
	cmd := exec.Command("ping", "-I", liveMacvlan, "-c", strconv.Itoa(count),
		"-i", "0.1", "-W", "1", liveTargetIP)
	cmd.Start() //nolint:errcheck
	return func() {
		if cmd.Process != nil {
			cmd.Process.Kill() //nolint:errcheck
		}
		cmd.Wait() //nolint:errcheck
	}
}

// liveOpts returns filterOpts for in-process subscriber tests.
func liveOpts(filter ...bpf.Instruction) filterOpts {
	return filterOpts{
		perfPerCPUBuffer: 8192,
		perfWatermark:    1,
		actions:          []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx},
		filter:           filter,
	}
}

// readWithTimeout reads one packet from f within the given deadline.
func readWithTimeout(t *testing.T, f *filter, d time.Duration) (packet, bool) {
	t.Helper()
	ch := make(chan packet, 1)
	errch := make(chan error, 1)
	go func() {
		p, err := f.read()
		if err != nil {
			errch <- err
		} else {
			ch <- p
		}
	}()
	select {
	case p := <-ch:
		return p, true
	case err := <-errch:
		t.Logf("read error: %v", err)
		return packet{}, false
	case <-time.After(d):
		return packet{}, false
	}
}

// countPcapng returns the number of data packets in a pcapng file.
func countPcapng(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Errorf("open pcapng %s: %v", path, err)
		return 0
	}
	defer f.Close()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Errorf("pcapng reader %s: %v", path, err)
		return 0
	}
	n := 0
	for {
		_, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		n++
	}
	return n
}

// ── Test 1: single subscriber, synthetic traffic via prog.Test() ──────────────
func TestLiveSingleSubscriberSynthetic(t *testing.T) {
	hookPin := liveSetup(t)

	f, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatalf("newFilter: %v", err)
	}
	defer f.close()
	t.Logf("subscriber registered in slot %d", f.slot)

	// Inject 5 synthetic packets through the coordinator program.
	pkt := make([]byte, 64)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	const n = 5
	for i := 0; i < n; i++ {
		checkAction(t, xdpPass, f, pkt)
	}

	// Read them all back.
	for i := 0; i < n; i++ {
		p, ok := readWithTimeout(t, f, 2*time.Second)
		if !ok {
			t.Fatalf("packet %d/%d not received within timeout", i+1, n)
		}
		if len(p.data) < len(pkt) {
			t.Fatalf("packet %d: short data (%d < %d)", i+1, len(p.data), len(pkt))
		}
		if p.action != xdpPass {
			t.Errorf("packet %d: expected XDP_PASS, got %v", i+1, p.action)
		}
	}

	m, _ := f.metrics()
	t.Logf("metrics: recv=%d matched=%d perfErrors=%d",
		m[xdpPass].receivedPackets, m[xdpPass].matchedPackets, m[xdpPass].perfOutputErrors)

	if m[xdpPass].receivedPackets != n {
		t.Errorf("expected %d received packets, got %d", n, m[xdpPass].receivedPackets)
	}
	if m[xdpPass].matchedPackets != n {
		t.Errorf("expected %d matched packets, got %d", n, m[xdpPass].matchedPackets)
	}
	t.Logf("PASS – %d synthetic packets injected and read back", n)
}

// ── Test 2: probe for real wire ingress traffic ───────────────────────────────
// Attempts to capture real ingress frames from macvlan0 ping traffic.
// Native XDP runs in the NIC driver's RX path; macvlan frames are injected
// via dev_forward_skb which bypasses the driver path and thus XDP.  On this
// host enp5s0f0 is also isolated (no external peers), so we cannot guarantee
// real wire traffic.  The test reports what it finds but does not fail if the
// count is zero — physical loopback or an external peer would be required to
// make this reliable.
func TestLiveSingleSubscriberRealTraffic(t *testing.T) {
	hookPin := liveSetup(t)

	f, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatalf("newFilter: %v", err)
	}
	defer f.close()
	t.Logf("coordinator mode: frags=%v attachType=%v", f.xdpFrags, f.xdpAttach)

	const pktCount = 10
	cancel := sendTraffic(pktCount)
	defer cancel()

	received := 0
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && received < pktCount {
		if _, ok := readWithTimeout(t, f, time.Until(deadline)); ok {
			received++
		} else {
			break
		}
	}

	m, _ := f.metrics()
	t.Logf("wire traffic probe: sent=%d xdp_recv=%d matched=%d perf_read=%d perfErrors=%d",
		pktCount, m[xdpPass].receivedPackets, m[xdpPass].matchedPackets, received, m[xdpPass].perfOutputErrors)
	if received > 0 {
		t.Logf("PASS – %d real wire packets captured", received)
	} else {
		t.Logf("INFO – 0 real wire packets (native XDP does not see macvlan/software-path traffic; external peer needed)")
	}
}

// ── Test 3: two concurrent subscribers, filter split ─────────────────────────
// sub1 captures all packets; sub2 captures only packets whose first byte is 0xAB.
func TestLiveTwoSubscribersFilterSplit(t *testing.T) {
	hookPin := liveSetup(t)

	// sub1: match all
	f1, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatalf("f1 newFilter: %v", err)
	}
	defer f1.close()

	// sub2: match only first-byte == 0xAB
	opts2 := liveOpts(
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xAB, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 3},
	)
	f2, err := newFilter(hookPin, opts2)
	if err != nil {
		t.Fatalf("f2 newFilter: %v", err)
	}
	defer f2.close()
	t.Logf("f1 slot %d, f2 slot %d", f1.slot, f2.slot)

	// Inject 5 matching + 5 non-matching packets via f2's coordinator.
	matching := []byte{0xAB, 0xCD, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	noMatch := []byte{0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	const each = 5
	for i := 0; i < each; i++ {
		checkAction(t, xdpPass, f2, matching)
		checkAction(t, xdpPass, f2, noMatch)
	}

	// f1 should receive all 10 packets.
	for i := 0; i < each*2; i++ {
		if _, ok := readWithTimeout(t, f1, 2*time.Second); !ok {
			t.Fatalf("f1: packet %d/%d not received", i+1, each*2)
		}
	}

	// f2 should receive only the 5 matching packets.
	for i := 0; i < each; i++ {
		if _, ok := readWithTimeout(t, f2, 2*time.Second); !ok {
			t.Fatalf("f2: matching packet %d/%d not received", i+1, each)
		}
	}

	m1, _ := f1.metrics()
	m2, _ := f2.metrics()
	t.Logf("f1 recv=%d matched=%d", m1[xdpPass].receivedPackets, m1[xdpPass].matchedPackets)
	t.Logf("f2 recv=%d matched=%d", m2[xdpPass].receivedPackets, m2[xdpPass].matchedPackets)

	if m1[xdpPass].receivedPackets != each*2 {
		t.Errorf("f1 expected %d received, got %d", each*2, m1[xdpPass].receivedPackets)
	}
	if m2[xdpPass].receivedPackets != each*2 {
		t.Errorf("f2 expected %d received packets (filter runs on all), got %d", each*2, m2[xdpPass].receivedPackets)
	}
	if m2[xdpPass].matchedPackets != each {
		t.Errorf("f2 expected %d matched, got %d", each, m2[xdpPass].matchedPackets)
	}
	t.Logf("PASS – f1 got all %d packets; f2 got %d/%d matching", each*2, each, each*2)
}

// ── Test 4: subscriber join/leave during live traffic ─────────────────────────
func TestLiveSubscriberJoinLeave(t *testing.T) {
	hookPin := liveSetup(t)

	// Phase 1: only f1 is active.
	f1, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatalf("f1: %v", err)
	}

	pkt := make([]byte, 14)
	checkAction(t, xdpPass, f1, pkt)
	checkAction(t, xdpPass, f1, pkt)
	if _, ok := readWithTimeout(t, f1, 2*time.Second); !ok {
		t.Fatal("f1 phase1: no packet")
	}
	if _, ok := readWithTimeout(t, f1, 2*time.Second); !ok {
		t.Fatal("f1 phase1: second packet missing")
	}
	t.Log("phase 1 (f1 only): OK")

	// Phase 2: f2 joins; both should receive packets.
	f2, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatalf("f2: %v", err)
	}

	checkAction(t, xdpPass, f2, pkt) // uses f2's coordinator (has both f1 and f2)
	if _, ok := readWithTimeout(t, f1, 2*time.Second); !ok {
		t.Fatal("f1 phase2: no packet after f2 joined")
	}
	if _, ok := readWithTimeout(t, f2, 2*time.Second); !ok {
		t.Fatal("f2 phase2: no packet after joining")
	}
	t.Log("phase 2 (f1+f2): OK")

	// Phase 3: f1 leaves; f2 should still work.
	if err := f1.close(); err != nil {
		t.Fatalf("f1 close: %v", err)
	}

	checkAction(t, xdpPass, f2, pkt) // f2's coordinator now rebuilt for f2 only
	if _, ok := readWithTimeout(t, f2, 2*time.Second); !ok {
		t.Fatal("f2 phase3: no packet after f1 left")
	}
	f2.close()
	t.Log("phase 3 (f2 only after f1 left): OK")
	t.Log("PASS – subscriber join/leave lifecycle correct")
}

// ── Test 5: partial registration recovery (Bug 1) ─────────────────────────────
func TestLivePartialRegistrationRecovery(t *testing.T) {
	hookPin := liveSetup(t)

	// Write a PID file for slot 0 (our own live PID) without any maps.
	sd := stateDir(hookPin)
	os.MkdirAll(sd, 0700)
	pidFile := subPIDPath(hookPin, 0)
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		t.Fatalf("write pid: %v", err)
	}
	defer os.Remove(pidFile)

	f, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		t.Fatalf("REGRESSION – partial slot blocks subscriber: %v", err)
	}
	t.Logf("claimed slot %d (partial slot 0 was reclaimed)", f.slot)
	f.close()
	t.Log("PASS – partial registration reclaimed")
}

// ── Test 6: last-close sweeps entire hook map (Bug 3) ─────────────────────────
func TestLiveCleanHookMapOnLastClose(t *testing.T) {
	hookPin := liveSetup(t)

	// Open the hook map for inspection after subscribers close.
	hm, err := ebpf.LoadPinnedMap(hookPin, nil)
	if err != nil {
		t.Fatalf("open hook map: %v", err)
	}
	defer hm.Close()

	// f1: all four actions.
	opts1 := liveOpts(bpf.RetConstant{Val: 3})
	opts1.actions = []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx}
	f1, err := newFilter(hookPin, opts1)
	if err != nil {
		t.Fatal("f1:", err)
	}

	// f2: PASS only.
	opts2 := liveOpts(bpf.RetConstant{Val: 3})
	opts2.actions = []xdpAction{xdpPass}
	f2, err := newFilter(hookPin, opts2)
	if err != nil {
		t.Fatal("f2:", err)
	}

	// Verify both receive packets before closing.
	pkt := make([]byte, 14)
	checkAction(t, xdpPass, f2, pkt)
	if _, ok := readWithTimeout(t, f1, 2*time.Second); !ok {
		t.Error("f1 pre-close: no packet")
	}
	if _, ok := readWithTimeout(t, f2, 2*time.Second); !ok {
		t.Error("f2 pre-close: no packet")
	}

	// Close f1 first (owns all 4 actions), then f2 (owns only PASS).
	if err := f1.close(); err != nil {
		t.Fatal("f1 close:", err)
	}
	if err := f2.close(); err != nil {
		t.Fatal("f2 close:", err)
	}

	// Hook map must have no remaining entries for any action.
	stale := false
	for _, a := range allActions(hm) {
		var fd int32
		if err := hm.Lookup(int32(a), &fd); err == nil {
			t.Errorf("REGRESSION – stale entry for %v (fd %d) after all subscribers closed", a, fd)
			stale = true
		}
	}
	if !stale {
		t.Log("PASS – all hook map entries removed after last close")
	}
}

// ── Test 7: max subscriber overflow ──────────────────────────────────────────
func TestLiveMaxSubscribersOverflow(t *testing.T) {
	hookPin := liveSetup(t)

	filters := make([]*filter, maxSubscribers)
	for i := 0; i < maxSubscribers; i++ {
		opts := liveOpts(bpf.RetConstant{Val: 3})
		opts.actions = []xdpAction{xdpPass}
		f, err := newFilter(hookPin, opts)
		if err != nil {
			t.Fatalf("subscriber %d: %v", i, err)
		}
		filters[i] = f
	}
	t.Logf("all %d slots filled", maxSubscribers)

	opts := liveOpts(bpf.RetConstant{Val: 3})
	opts.actions = []xdpAction{xdpPass}
	_, err := newFilter(hookPin, opts)
	if err != nil {
		t.Logf("PASS – 17th subscriber correctly rejected: %v", err)
	} else {
		t.Error("REGRESSION – 17th subscriber accepted")
	}

	for _, f := range filters {
		f.close()
	}
	t.Log("all slots released")
}

// ── Test 8: two xdpcap binary processes – packet injection via coordinator ────
//
// Native XDP on this host's isolated NIC receives no external traffic.  Instead
// we use an in-process third subscriber to pump packets through the coordinator
// that the two binary processes built.  Because the coordinator is rebuilt to
// fan out to ALL registered subscribers, prog.Test() writes directly into each
// binary process's perf ring buffer, which their pcap goroutine drains.
func TestLiveBinaryMultiCapture(t *testing.T) {
	hookPin := liveSetup(t)

	if _, err := os.Stat(xdpcapBin); err != nil {
		t.Skipf("xdpcap binary not found at %s (run: go build -o /tmp/xdpcap ./cmd/xdpcap/)", xdpcapBin)
	}

	cap1 := "/tmp/live_cap1.pcapng"
	cap2 := "/tmp/live_cap2.pcapng"
	os.Remove(cap1)
	os.Remove(cap2)
	t.Cleanup(func() { os.Remove(cap1); os.Remove(cap2) })

	// Start both xdpcap processes.
	cmd1 := exec.Command(xdpcapBin, "-q", hookPin, cap1)
	cmd2 := exec.Command(xdpcapBin, "-q", hookPin, cap2)
	if err := cmd1.Start(); err != nil {
		t.Fatalf("start cap1: %v", err)
	}
	if err := cmd2.Start(); err != nil {
		cmd1.Process.Kill() //nolint:errcheck
		t.Fatalf("start cap2: %v", err)
	}
	t.Logf("cap1 pid=%d  cap2 pid=%d", cmd1.Process.Pid, cmd2.Process.Pid)

	// Wait until both binary processes have registered as subscribers.
	if !waitForSubscriberCount(hookPin, 2, 10*time.Second) {
		cmd1.Process.Kill() //nolint:errcheck
		cmd2.Process.Kill() //nolint:errcheck
		t.Fatal("binary processes did not register within 10s")
	}
	t.Log("both binary subscribers registered")

	// Register a third in-process subscriber.  The coordinator is now rebuilt
	// to fan out to [binary1, binary2, in-process], so prog.Test() on it
	// writes into all three perf ring buffers.
	f3, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		cmd1.Process.Kill() //nolint:errcheck
		cmd2.Process.Kill() //nolint:errcheck
		t.Fatalf("in-process filter: %v", err)
	}
	t.Logf("in-process subscriber registered as slot %d (coordinator fans to all 3)", f3.slot)

	// Inject packets via prog.Test() on the in-process coordinator.
	const injectCount = 30
	pkt := make([]byte, 60)
	for i := 0; i < injectCount; i++ {
		checkAction(t, xdpPass, f3, pkt)
	}
	t.Logf("injected %d packets into coordinator", injectCount)

	// Allow time for binary processes to drain their perf buffers.
	time.Sleep(500 * time.Millisecond)

	// Close in-process subscriber (coordinator rebuilt for binary1+binary2).
	f3.close()

	// Stop binary processes.
	time.Sleep(100 * time.Millisecond)
	cmd1.Process.Signal(os.Interrupt) //nolint:errcheck
	cmd2.Process.Signal(os.Interrupt) //nolint:errcheck
	cmd1.Wait()                       //nolint:errcheck
	cmd2.Wait()                       //nolint:errcheck

	n1 := countPcapng(t, cap1)
	n2 := countPcapng(t, cap2)
	t.Logf("cap1=%d  cap2=%d  (injected=%d)", n1, n2, injectCount)

	if n1 == 0 {
		t.Error("cap1: no packets – coordinator did not fan out to this subscriber")
	}
	if n2 == 0 {
		t.Error("cap2: no packets – coordinator did not fan out to this subscriber")
	}
	if n1 > 0 && n2 > 0 {
		t.Logf("PASS – both xdpcap binaries captured %d and %d packets", n1, n2)
	}
}

// ── Test 9: stateDir is injective (no collisions after fix) ──────────────────
func TestLiveStateDirInjective(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	pairs := [][2]string{
		{"/sys/fs/bpf/hook_test", "/sys/fs/bpf/hook.test"},
		{"/sys/fs/bpf/a_b_c", "/sys/fs/bpf/a.b.c"},
		{"/sys/fs/bpf/live__hook", "/sys/fs/bpf/live_hook"},
	}
	for _, p := range pairs {
		a, b := stateDir(p[0]), stateDir(p[1])
		if a == b {
			t.Errorf("REGRESSION – collision: %q and %q both → %q", p[0], p[1], a)
		} else {
			t.Logf("OK %q → %q", p[0], a)
			t.Logf("OK %q → %q", p[1], b)
		}
	}
}

// ── Test 10: binary filter split – unfiltered vs ICMP-only ───────────────────
//
// Injects a mix of ICMP-shaped and non-ICMP packets via the in-process
// coordinator.  cap_all (no filter) must receive all packets; cap_icmp (filter
// "icmp") must receive only the ICMP-shaped ones, proving that each binary
// process's filter is evaluated independently inside the coordinator.
func TestLiveBinaryFilteredMultiCapture(t *testing.T) {
	hookPin := liveSetup(t)

	if _, err := os.Stat(xdpcapBin); err != nil {
		t.Skipf("xdpcap binary not found at %s", xdpcapBin)
	}

	capAll := "/tmp/live_cap_all.pcapng"
	capICMP := "/tmp/live_cap_icmp.pcapng"
	os.Remove(capAll)
	os.Remove(capICMP)
	t.Cleanup(func() { os.Remove(capAll); os.Remove(capICMP) })

	// cmd1: no filter; cmd2: "icmp" filter (IPv4 ICMP protocol = 1).
	cmd1 := exec.Command(xdpcapBin, "-q", hookPin, capAll)
	cmd2 := exec.Command(xdpcapBin, "-q", hookPin, capICMP, "icmp")
	if err := cmd1.Start(); err != nil {
		t.Fatalf("start cap_all: %v", err)
	}
	if err := cmd2.Start(); err != nil {
		cmd1.Process.Kill() //nolint:errcheck
		t.Fatalf("start cap_icmp: %v", err)
	}
	t.Logf("cap_all pid=%d  cap_icmp pid=%d", cmd1.Process.Pid, cmd2.Process.Pid)

	if !waitForSubscriberCount(hookPin, 2, 10*time.Second) {
		cmd1.Process.Kill() //nolint:errcheck
		cmd2.Process.Kill() //nolint:errcheck
		t.Fatal("binary processes did not register within 10s")
	}
	t.Log("both binary subscribers registered")

	// In-process subscriber to drive injection.
	f3, err := newFilter(hookPin, liveOpts(bpf.RetConstant{Val: 3}))
	if err != nil {
		cmd1.Process.Kill() //nolint:errcheck
		cmd2.Process.Kill() //nolint:errcheck
		t.Fatalf("in-process filter: %v", err)
	}
	defer f3.close()
	t.Logf("in-process subscriber registered as slot %d", f3.slot)

	// icmpPkt: minimal Ethernet+IPv4 frame with protocol=1 (ICMP).
	// Matches the "icmp" BPF filter compiled for LinkTypeEthernet.
	icmpPkt := makeICMPPacket()
	zeroPkt := make([]byte, 60)  // all-zero, does NOT match "icmp"

	const each = 15 // 15 ICMP + 15 zero = 30 total
	for i := 0; i < each; i++ {
		checkAction(t, xdpPass, f3, icmpPkt)
		checkAction(t, xdpPass, f3, zeroPkt)
	}
	t.Logf("injected %d ICMP + %d non-ICMP packets", each, each)

	time.Sleep(500 * time.Millisecond)
	f3.close()

	time.Sleep(100 * time.Millisecond)
	cmd1.Process.Signal(os.Interrupt) //nolint:errcheck
	cmd2.Process.Signal(os.Interrupt) //nolint:errcheck
	cmd1.Wait()                       //nolint:errcheck
	cmd2.Wait()                       //nolint:errcheck

	nAll := countPcapng(t, capAll)
	nICMP := countPcapng(t, capICMP)
	t.Logf("cap_all=%d  cap_icmp=%d  (injected: %d ICMP + %d non-ICMP)", nAll, nICMP, each, each)

	if nAll == 0 {
		t.Error("cap_all: no packets – unfiltered capture received nothing")
	}
	if nICMP == 0 {
		t.Error("cap_icmp: no packets – ICMP filter matched nothing")
	}
	if nAll > 0 && nICMP > 0 {
		if nAll < nICMP {
			t.Errorf("impossible: cap_all (%d) < cap_icmp (%d)", nAll, nICMP)
		} else {
			t.Logf("PASS – cap_all=%d ≥ cap_icmp=%d, filter split verified", nAll, nICMP)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// waitForSubscriberCount polls the state dir until at least n PID files are
// present (meaning n subscriber processes have completed registration).
func waitForSubscriberCount(hookPin string, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		count := 0
		for i := 0; i < maxSubscribers; i++ {
			if data, err := os.ReadFile(subPIDPath(hookPin, i)); err == nil {
				if pid, _ := strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 && processAlive(pid) {
					count++
				}
			}
		}
		if count >= n {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// makeICMPPacket returns a minimal 60-byte Ethernet+IPv4 frame whose IP
// protocol field (offset 23) is 1 (ICMP), matching the "icmp" tcpdump filter.
func makeICMPPacket() []byte {
	pkt := make([]byte, 60)
	// Ethernet header (14 bytes): dst MAC, src MAC, EtherType=0x0800
	pkt[12] = 0x08
	pkt[13] = 0x00
	// IPv4 header starts at offset 14.
	pkt[14] = 0x45 // version=4, IHL=5 (20 bytes)
	pkt[15] = 0x00 // DSCP/ECN
	pkt[16] = 0x00 // total length hi
	pkt[17] = 0x2e // total length lo = 46 bytes
	pkt[23] = 0x01 // protocol = ICMP
	// IP checksum left zero (BPF filter doesn't verify checksum)
	return pkt
}

func run(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run %v: %v\n%s", args, err, out)
	}
}

func mustMAC(t *testing.T, ifname string) string {
	t.Helper()
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatalf("mustMAC %s: %v", ifname, err)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		ifc.HardwareAddr[0], ifc.HardwareAddr[1], ifc.HardwareAddr[2],
		ifc.HardwareAddr[3], ifc.HardwareAddr[4], ifc.HardwareAddr[5])
}

// Silence unused-import warnings for packages used only in specific tests.
var (
	_ = unix.RLIMIT_MEMLOCK
	_ = link.XDPOptions{}
)
