// Program xdpcap produces tcpdump compatible PCAPs from a BPF map.
//
// You can use it to introspect traffic dropped or redirected by XDP. It
// is also useful to examine any transformations done to a packet.
//
// xdpcap requires you to instrument your XDP code in a specific way,
// check the documentation at https://github.com/cloudflare/xdpcap
// for details.
//
// Once you have done so, you can capture into a file, or pipe
// straight into tcpdump:
//
//	xdpcap /path/to/pinned/map file.pcap
//	xdpcap /path/to/pinned/map - | tcpdump -r -
//
// xdpcap supports tcpdump / libpcap-style filter expressions.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

func main() {
	flags, err := parseFlags(os.Args[0], os.Args[1:])
	switch {
	case err == flag.ErrHelp:
		fmt.Fprintln(os.Stderr, flags.Usage())
		os.Exit(0)

	case err != nil:
		fmt.Fprintf(os.Stderr, "Error: %v\n\nUsage: %s", err, flags.Usage())
		os.Exit(1)
	}
	defer flags.pcapFile.Close()

	err = capture(flags)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}

func capture(flags flags) error {
	// BPF progs, maps and the perf buffer are stored in locked memory
	err := unlimitLockedMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error setting locked memory limit:", err)
	}

	// Exit gracefully
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	filter, err := newFilter(flags.mapPath, flags.filterOpts)
	if err != nil {
		return errors.Wrap(err, "creating filter")
	}

	// Need to close the filter after the pcap writer

	pcapWriter, interfaces, err := newPcapWriter(flags.pcapFile, flags.filterExpr, filter.actions)
	if err != nil {
		filter.close()
		return errors.Wrap(err, "writing pcap header")
	}
	defer pcapWriter.Flush()
	defer filter.close()

	if !flags.quiet {
		// Print metrics every 1 second
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for range ticker.C {
				str := bytes.Buffer{}

				metrics, err := filter.metrics()
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting metrics:", err)
					continue
				}

				for _, action := range filter.actions {
					fmt.Fprintf(&str, "%v: %d/%d\t", action, metrics[action].receivedPackets, metrics[action].matchedPackets)
				}

				str.WriteString("(received/matched packets)\n")
				os.Stderr.WriteString(str.String())
			}
		}()
	}

	// Write out a pcap file from aggregated packets
	var packetCount uint64
	var capturedBytes uint64
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			// Check packet limit
			if flags.packetLimit > 0 && packetCount >= flags.packetLimit {
				if !flags.quiet {
					fmt.Fprintf(os.Stderr, "\nPacket limit reached: %d packets captured\n", packetCount)
				}
				return
			}

			// Check size limit (convert MB to bytes)
			if flags.sizeLimit > 0 && capturedBytes >= flags.sizeLimit*1024*1024 {
				if !flags.quiet {
					fmt.Fprintf(os.Stderr, "\nSize limit reached: %.2f MB captured\n", float64(capturedBytes)/(1024*1024))
				}
				return
			}

			pkt, err := filter.read()
			switch {
			case err == errFilterClosed:
				return
			case err != nil:
				fmt.Fprintln(os.Stderr, "Error:", err)
				continue
			}

			info := gopacket.CaptureInfo{
				Timestamp:      time.Now(),
				CaptureLength:  len(pkt.data),
				Length:         len(pkt.data),
				InterfaceIndex: interfaces[pkt.action],
			}

			err = pcapWriter.WritePacket(info, pkt.data)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error writing packet:", err)
			}

			packetCount++
			capturedBytes += uint64(len(pkt.data))

			if flags.flush {
				err = pcapWriter.Flush()
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error flushing data:", err)
				}
			}
		}
	}()

	select {
	case <-sigs:
		return nil
	case <-done:
		return nil
	}
}

// newPcapWriter creates a pcapWriter with an pcap interface (metadata) per xdp action
func newPcapWriter(w io.Writer, filterExpr string, actions []xdpAction) (*pcapgo.NgWriter, map[xdpAction]int, error) {
	if len(actions) == 0 {
		return nil, nil, errors.New("can't create pcap with no actions")
	}

	var interfaces []pcapgo.NgInterface
	actionIfcs := make(map[xdpAction]int)

	for id, action := range actions {
		interfaces = append(interfaces, pcapgo.NgInterface{
			Name:       fmt.Sprintf("XDP%s", action.String()),
			Comment:    "XDP action",
			Filter:     filterExpr,
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		})
		actionIfcs[action] = id
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(w, interfaces[0], pcapgo.NgWriterOptions{})
	if err != nil {
		return nil, nil, err
	}

	for _, ifc := range interfaces[1:] {
		_, err := pcapWriter.AddInterface(ifc)
		if err != nil {
			return nil, nil, err
		}
	}

	// Flush the header out in case we're writing to stdout, this lets tcpdump print a reassuring message
	err = pcapWriter.Flush()
	if err != nil {
		return nil, nil, errors.Wrap(err, "writing pcap header")
	}

	return pcapWriter, actionIfcs, nil
}
