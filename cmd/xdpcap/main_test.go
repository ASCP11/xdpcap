package main

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

// TestCaptureInterruptWhileWriting interrupts a capture while packets are
// flowing and checks the resulting pcap is complete and readable.
func TestCaptureInterruptWhileWriting(t *testing.T) {
	hp := bpfTempPath(t)
	hm := hookMap(t, len(xdpActions))
	if err := hm.Pin(hp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(hp) })

	out, err := os.Create(filepath.Join(t.TempDir(), "out.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	opts := testOpts(bpf.RetConstant{Val: 1500})
	opts.actions = []xdpAction{xdpPass}
	captureErr := make(chan error, 1)
	go func() {
		captureErr <- capture(flags{mapPath: hp, pcapFile: out, filterOpts: opts})
	}()

	// Wait for the coordinator to be installed, then feed it packets.
	var prog *ebpf.Program
	for deadline := time.Now().Add(5 * time.Second); prog == nil; {
		var id uint32
		if err := hm.Lookup(int32(xdpPass), &id); err == nil {
			if prog, err = ebpf.NewProgramFromID(ebpf.ProgramID(id)); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("coordinator never installed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer prog.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pkt := make([]byte, 64)
		for {
			select {
			case <-stop:
				return
			default:
				prog.Test(pkt) //nolint:errcheck
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := <-captureErr; err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()

	if _, err := out.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	r, err := pcapgo.NewNgReader(out, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("pcap corrupt after %d packets: %v", n, err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no packets captured")
	}
	t.Logf("read back %d packets", n)
}
