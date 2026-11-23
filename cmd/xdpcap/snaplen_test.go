package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket/pcapgo"
)

// These tests don't need root: they don't create maps or load programs.

func TestSnaplenFlag(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{"-snaplen", "96", "foo", output})
	if err != nil {
		t.Fatal(err)
	}
	expected := defaultFlags("foo")
	expected.snaplen = 96
	expected.filterOpts.snaplen = 96
	requireFlags(t, output, expected, flags)

	flags, err = parseFlags("", []string{"-snaplen", "65535", "foo", output})
	if err != nil {
		t.Fatal(err)
	}
	if flags.filterOpts.snaplen != 65535 {
		t.Fatalf("snaplen %d, expected 65535", flags.filterOpts.snaplen)
	}

	for _, bad := range []string{"-1", "65536", "1000000", "abc"} {
		if _, err := parseFlags("", []string{"-snaplen", bad, "foo", output}); err == nil {
			t.Errorf("-snaplen %s accepted", bad)
		}
	}
}

func TestSnaplenFlagRejectedBeforeOutput(t *testing.T) {
	output := tempOutput(t)

	if _, err := parseFlags("", []string{"-snaplen", "-1", "foo", output}); err == nil {
		t.Fatal("negative snaplen accepted")
	}
	if _, err := parseFlags("", []string{"-cleanup", "-snaplen", "-1", "foo"}); err == nil {
		t.Fatal("negative snaplen accepted with -cleanup")
	}
}

func TestSnaplenUsage(t *testing.T) {
	flags, _ := parseFlags("", []string{"-help"})
	if !bytes.Contains([]byte(flags.Usage()), []byte("-snaplen")) {
		t.Fatal("-snaplen missing from usage")
	}
}

// sample builds a perf sample like the kernel does: header, captured bytes and
// padding up to a multiple of 8 bytes (including the 4 byte size field).
func sample(word, capLen uint64, data []byte) []byte {
	raw := make([]byte, 16, 16+len(data)+8)
	nativeEndian.PutUint64(raw[:8], word)
	nativeEndian.PutUint64(raw[8:16], capLen)
	raw = append(raw, data...)
	for (len(raw)+4)%8 != 0 {
		raw = append(raw, 0xff)
	}
	return raw
}

func TestParseSample(t *testing.T) {
	pkt := make([]byte, 200)
	for i := range pkt {
		pkt[i] = byte(i)
	}

	// Format without snaplen: original length is the captured length.
	got, err := parseSample(sample(uint64(xdpDrop), 200, pkt), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.action != xdpDrop || got.length != 200 || !bytes.Equal(got.data, pkt) {
		t.Fatalf("unexpected packet %v %d %d", got.action, got.length, len(got.data))
	}

	// Truncated by the kernel: original length in the action word.
	got, err = parseSample(sample(uint64(xdpPass)|200<<32, 64, pkt[:64]), 64)
	if err != nil {
		t.Fatal(err)
	}
	if got.action != xdpPass || got.length != 200 || !bytes.Equal(got.data, pkt[:64]) {
		t.Fatalf("unexpected packet %v %d %d", got.action, got.length, len(got.data))
	}

	// Whole packet from a coordinator without snaplen support: truncated here.
	got, err = parseSample(sample(uint64(xdpTx), 200, pkt), 64)
	if err != nil {
		t.Fatal(err)
	}
	if got.action != xdpTx || got.length != 200 || !bytes.Equal(got.data, pkt[:64]) {
		t.Fatalf("unexpected packet %v %d %d", got.action, got.length, len(got.data))
	}

	if _, err := parseSample(sample(uint64(xdpPass), 300, pkt), 0); err == nil {
		t.Fatal("sample shorter than captured length accepted")
	}
	if _, err := parseSample(sample(uint64(xdpPass)|10<<32, 64, pkt[:64]), 0); err == nil {
		t.Fatal("original length < captured length accepted")
	}
	if _, err := parseSample(make([]byte, 15), 0); err == nil {
		t.Fatal("short sample accepted")
	}
}

// perfCall is the state at a bpf_perf_event_output call.
type perfCall struct {
	flags  uint64
	header []byte // 16 bytes at R4, R5 long
}

// runPerfOutput interprets the instructions emitted by perfOutputInsns with
// R8 = pktLen, and returns the perf output call it makes. It only supports the
// handful of instructions perfOutputInsns uses.
func runPerfOutput(t *testing.T, insns asm.Instructions, pktLen uint64) perfCall {
	t.Helper()

	// The program must assemble, which resolves jump labels.
	if err := insns.Marshal(io.Discard, binary.LittleEndian); err != nil {
		t.Fatal("marshal:", err)
	}

	labels := map[string]int{}
	for i, ins := range insns {
		if sym := ins.Symbol(); sym != "" {
			labels[sym] = i
		}
	}

	const stackTop = 1 << 32
	stack := make([]byte, 512)
	var regs [11]uint64
	regs[asm.R6] = 0xc7c7 // ctx
	regs[asm.R8] = pktLen
	regs[asm.R10] = stackTop

	var calls []perfCall
	for pc := 0; pc < len(insns); pc++ {
		ins := insns[pc]
		op := ins.OpCode

		src := uint64(ins.Constant)
		if op.Source() == asm.RegSource {
			src = regs[ins.Src]
		}

		switch op.Class() {
		case asm.ALU64Class:
			switch op.ALUOp() {
			case asm.Mov:
				regs[ins.Dst] = src
			case asm.Add:
				regs[ins.Dst] += src
			case asm.LSh:
				regs[ins.Dst] <<= src
			case asm.Or:
				regs[ins.Dst] |= src
			default:
				t.Fatalf("unsupported instruction %v", ins)
			}

		case asm.LdClass:
			if !op.IsDWordLoad() {
				t.Fatalf("unsupported instruction %v", ins)
			}
			regs[ins.Dst] = uint64(ins.Constant)

		case asm.StClass, asm.StXClass:
			if op.Size() != asm.DWord {
				t.Fatalf("unsupported instruction %v", ins)
			}
			val := uint64(ins.Constant)
			if op.Class() == asm.StXClass {
				val = regs[ins.Src]
			}
			off := int(regs[ins.Dst]+uint64(int64(ins.Offset))) - stackTop + len(stack)
			nativeEndian.PutUint64(stack[off:off+8], val)

		case asm.JumpClass:
			switch op.JumpOp() {
			case asm.JLE:
				if regs[ins.Dst] <= src {
					pc = labels[ins.Reference()] - 1
				}
			case asm.Call:
				if ins.Constant != int64(asm.FnPerfEventOutput) {
					t.Fatalf("unexpected call %v", ins)
				}
				if regs[asm.R1] != 0xc7c7 {
					t.Fatal("ctx not passed in R1")
				}
				off := int(regs[asm.R4]) - stackTop + len(stack)
				calls = append(calls, perfCall{
					flags:  regs[asm.R3],
					header: append([]byte(nil), stack[off:off+int(regs[asm.R5])]...),
				})
				regs[asm.R0] = 0
			default:
				t.Fatalf("unsupported instruction %v", ins)
			}

		default:
			t.Fatalf("unsupported instruction %v", ins)
		}
	}

	if len(calls) != 1 {
		t.Fatalf("%d perf output calls, expected 1", len(calls))
	}
	if regs[asm.R8] != pktLen || regs[asm.R6] != 0xc7c7 || regs[asm.R7] != 0 {
		t.Fatal("callee-saved registers clobbered")
	}
	return calls[0]
}

func TestPerfOutputInsnsSnaplen(t *testing.T) {
	for _, tc := range []struct {
		snaplen, pktLen, capLen uint64
	}{
		{0, 60, 60},
		{0, 9000, 9000},
		{64, 60, 60},
		{64, 64, 64},
		{64, 65, 64},
		{64, 1500, 64},
		{65535, 9000, 9000},
	} {
		insns := perfOutputInsns(3, xdpRedirect, uint32(tc.snaplen), "s0_caplen")
		call := runPerfOutput(t, insns, tc.pktLen)

		if got := call.flags >> 32; got != tc.capLen {
			t.Errorf("snaplen %d len %d: %d bytes copied to perf ring, expected %d", tc.snaplen, tc.pktLen, got, tc.capLen)
		}
		if got := call.flags & math.MaxUint32; got != uint64(BPF_F_CURRENT_CPU) {
			t.Errorf("snaplen %d: flags index %#x", tc.snaplen, got)
		}
		if len(call.header) != 16 {
			t.Fatalf("header is %d bytes", len(call.header))
		}

		word := nativeEndian.Uint64(call.header[:8])
		if tc.snaplen == 0 && word != uint64(xdpRedirect) {
			t.Errorf("header without snaplen changed: action word %#x", word)
		}

		// Round trip through the reader, as the kernel would send it.
		pkt := make([]byte, tc.pktLen)
		for i := range pkt {
			pkt[i] = byte(i)
		}
		raw := sample(word, nativeEndian.Uint64(call.header[8:]), pkt[:call.flags>>32])
		got, err := parseSample(raw, uint32(tc.snaplen))
		if err != nil {
			t.Fatal(err)
		}
		if got.action != xdpRedirect || uint64(got.length) != tc.pktLen || !bytes.Equal(got.data, pkt[:tc.capLen]) {
			t.Errorf("snaplen %d len %d: got action %v length %d caplen %d", tc.snaplen, tc.pktLen, got.action, got.length, len(got.data))
		}
	}
}

func TestPcapngSnaplen(t *testing.T) {
	for _, tc := range []struct {
		snaplen, wantSnaplen uint32
	}{
		{0, 65535},
		{96, 96},
	} {
		var buf bytes.Buffer
		actions := []xdpAction{xdpDrop, xdpPass}
		w, interfaces, err := newPcapWriter(&buf, "tcp", actions, tc.snaplen)
		if err != nil {
			t.Fatal(err)
		}

		pkt := make([]byte, 1500)
		for i := range pkt {
			pkt[i] = byte(i)
		}
		packets := []packet{
			{action: xdpPass, data: pkt[:96], length: 1500}, // truncated
			{action: xdpDrop, data: pkt[:60], length: 60},   // shorter than snaplen
		}
		ts := time.Unix(1700000000, 0)
		for _, p := range packets {
			if err := w.WritePacket(captureInfo(p, ts, interfaces), p.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}

		r, err := pcapgo.NewNgReader(&buf, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range packets {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				t.Fatal(err)
			}
			if ci.CaptureLength != len(p.data) || ci.Length != p.length || !bytes.Equal(data, p.data) {
				t.Errorf("snaplen %d: got caplen %d len %d, expected %d %d", tc.snaplen, ci.CaptureLength, ci.Length, len(p.data), p.length)
			}
			if ci.InterfaceIndex != interfaces[p.action] {
				t.Errorf("interface %d, expected %d", ci.InterfaceIndex, interfaces[p.action])
			}
		}
		if _, _, err := r.ReadPacketData(); err != io.EOF {
			t.Fatalf("expected EOF, got %v", err)
		}

		if r.NInterfaces() != len(actions) {
			t.Fatalf("%d interfaces", r.NInterfaces())
		}
		for i := 0; i < r.NInterfaces(); i++ {
			ifc, err := r.Interface(i)
			if err != nil {
				t.Fatal(err)
			}
			if ifc.SnapLength != tc.wantSnaplen {
				t.Errorf("snaplen %d: interface %d SnapLength %d, expected %d", tc.snaplen, i, ifc.SnapLength, tc.wantSnaplen)
			}
		}
	}
}
