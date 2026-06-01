# xdpcap

xdpcap is a tcpdump-like capture tool for eXpress Data Path (XDP). It captures
packets and their XDP return codes from running XDP programs using standard
tcpdump / libpcap filter expressions, writing output as a pcapng file.

Multiple concurrent captures on the same hook are supported — each subscriber
gets its own filter and perf buffer, and a shared coordinator BPF program fans
packets out to all of them.


## Requirements

- Linux kernel 4.15+ (for `BPF_MAP_TYPE_PROG_ARRAY` tail-call support)
- Go 1.20+
- libpcap and its headers (`libpcap-dev` / `libpcap-devel`) for filter compilation
- Root privileges (or `CAP_BPF` + `CAP_NET_ADMIN` on kernels ≥ 5.8)


## Installation

### From source (recommended)

```bash
git clone https://github.com/cloudflare/xdpcap
cd xdpcap
go build -o xdpcap ./cmd/xdpcap
sudo install -m 755 xdpcap /usr/local/bin/xdpcap
```

### With `go install`

```bash
go install github.com/cloudflare/xdpcap/cmd/xdpcap@latest
```

The binary lands in `$(go env GOPATH)/bin/xdpcap`. Make sure that directory is
in your `PATH`, or copy the binary to `/usr/local/bin`.


## Instrumenting your XDP program

Your XDP program needs to expose a hook map and call `xdpcap_exit` instead of
returning directly.

### 1. Declare the hook map

Using the provided `hook.h` convenience macro:

```c
#include "hook.h"

struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();
```

Or declare it manually:

```c
struct bpf_map_def xdpcap_hook = {
    .type        = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = 5,   // one slot per XDP_* action
};
```

### 2. Replace `return XDP_*` with `xdpcap_exit`

```c
#include "hook.h"

struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();

int xdp_main(struct xdp_md *ctx) {
    // ... packet processing ...
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
}
```

`xdpcap_exit` tail-calls into the hook map and falls through to the original
action if no capture is attached, so there is zero overhead when xdpcap is not
running.

### 3. Pin the hook map to a bpffs path

The map must be pinned to a path inside a bpffs mount (typically `/sys/fs/bpf`)
so that xdpcap can open it by path. Using the Go loader:

```go
import "github.com/cloudflare/xdpcap"

hook, err := xdpcap.NewHook("/sys/fs/bpf/my_program_hook")
// ...
hook.Patch(collectionSpec, "xdpcap_hook")
// load and attach your collection, then:
hook.Pin()
```

For a complete example see [testdata/xdp_hook.c](testdata/xdp_hook.c).


## Usage

xdpcap requires root (or the capabilities listed above).

```
xdpcap [options] <hook map path> <output> [<filter expr>]
```

`<output>` may be `-` to write pcapng to stdout (implies `-q` and `-flush`).

`<filter expr>` is an optional tcpdump / libpcap expression. Omit it to capture
all packets. You can also pass a raw cBPF string in the form
`<count>,<op> <jt> <jf> <k>,...`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-actions <list>` | all | Comma-separated XDP actions to capture (`aborted`, `drop`, `pass`, `tx`, `redirect`, or numeric values) |
| `-buffer <bytes>` | 8192 | Per-CPU perf ring-buffer size |
| `-watermark <bytes>` | 1 | Perf wakeup watermark |
| `-c <count>` | unlimited | Stop after capturing this many packets |
| `-C <MB>` | unlimited | Stop after capturing approximately this many megabytes |
| `-flush` | off | Flush output after every packet (implied when writing to stdout) |
| `-linktype <type>` | ethernet | Link type for filter compilation |
| `-q` | off | Quiet — suppress per-second statistics |

### Examples

Capture all traffic to a file:
```bash
sudo xdpcap /sys/fs/bpf/my_hook dump.pcapng
```

Capture TCP port 80 only, pipe to tcpdump for live display:
```bash
sudo xdpcap /sys/fs/bpf/my_hook - "tcp and port 80" | sudo tcpdump -r -
```

Capture only dropped packets:
```bash
sudo xdpcap -actions drop /sys/fs/bpf/my_hook drops.pcapng
```

Run two concurrent captures on the same hook (different filters):
```bash
sudo xdpcap /sys/fs/bpf/my_hook all.pcapng &
sudo xdpcap /sys/fs/bpf/my_hook icmp-only.pcapng "icmp"
```

Stop after 1000 packets or 10 MB, whichever comes first:
```bash
sudo xdpcap -c 1000 -C 10 /sys/fs/bpf/my_hook capture.pcapng
```


## Multi-capture

Up to 16 concurrent xdpcap processes can attach to the same hook map. Each
subscriber registers independently — they can use different filters and action
sets. A shared coordinator BPF program (rebuilt whenever a subscriber joins or
leaves) fans packets to every active subscriber whose filter matches.

The coordinator is installed automatically on first attach and removed when the
last subscriber exits. Stale subscriber state from crashed processes is cleaned
up automatically.


## Limitations

- **Filters run on modified packets.** Filters are evaluated after the XDP
  program runs. If your program rewrites packets, write your filter to match the
  modified form.

- **Multi-buffer packets are truncated.** xdpcap captures only the first page
  of a packet. Programs loaded with `BPF_F_XDP_HAS_FRAGS` that process
  multi-page packets will produce truncated captures for those frames.


## Tests

Unit and integration tests require root:

```bash
sudo -E $(which go) test ./...
```

Live tests attach a real XDP hook to a named interface and exercise
multi-subscriber coordination end-to-end. They run as part of the normal test
suite when root is available:

```bash
sudo -E $(which go) test ./cmd/xdpcap/ -v -run TestLive -timeout 180s
```
