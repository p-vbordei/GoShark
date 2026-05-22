# GoShark

GoShark is a Go port of the Python [`pyshark`](https://github.com/KimiNewt/pyshark) library: a wrapper around TShark (the command-line interface to Wireshark) for packet capture and analysis in Go applications.

## Features

- **Multiple capture types** — file, live, remote, pipe, and in-memory captures
- **Flexible filtering** — Wireshark display filters and BPF capture filters
- **JSON / PDML / EK output** — parse TShark output in JSON, XML (PDML), or Elastic Common Schema form
- **Layer access** — ordered protocol layers with prefix-aware field lookup
- **Packet buffering** — eager `LoadPackets` with indexed access, or streaming callbacks
- **Raw packet data** — raw bytes, field offsets, and per-layer byte ranges (when the capture carries raw data)
- **Session tracking** — group packets into conversations by 5-tuple
- **Configuration & caching** — platform-specific config and cache directories

## Requirements

- Go 1.24 or higher
- Wireshark / TShark installed and on your `PATH` (live capture also needs `dumpcap`)

## Installation

Add GoShark to your project:

```bash
go get github.com/p-vbordei/GoShark
```

Then import the packages you need:

```go
import (
	"github.com/p-vbordei/GoShark/capture"
	"github.com/p-vbordei/GoShark/packet"
	"github.com/p-vbordei/GoShark/tshark"
)
```

## Environment Variables

- `TSHARK_PATH` — custom path to the `tshark` executable (otherwise found on `PATH`)
- `DUMPCAP_PATH` — custom path to the `dumpcap` executable (used for live captures)
- `GO_SHARK_CACHE_DIR` — override the default cache directory
- `GO_SHARK_CONFIG_DIR` — override the default config directory

## Project Structure

- `capture` — capture types (file, live, remote, pipe, in-memory) and the streaming engine
- `packet` — the `Packet` and `Layer` types, field access, and session tracking
- `tshark` — TShark process management, version detection, and JSON/PDML/EK parsers
- `config`, `cache` — configuration and output caching
- `utils`, `errors` — shared helpers and error types
- `tests` — integration tests and fixtures
- `docs/superpowers` — design spec and implementation plan

## Usage

### File capture

`ApplyOnPackets` streams packets to a callback; return `true` from the callback to stop early.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/p-vbordei/GoShark/capture"
	"github.com/p-vbordei/GoShark/packet"
)

func main() {
	cap, err := capture.NewFileCapture("capture.pcap",
		capture.WithDisplayFilter("tcp"),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = cap.ApplyOnPackets(func(p *packet.Packet) bool {
		sniffTime, _ := p.SniffTime()
		fmt.Printf("Packet %s | len=%s | highest=%s | %s\n",
			p.FrameNumber, p.FrameLen, p.HighestLayer(), sniffTime)
		return false // return true to stop early
	}, context.Background())
	if err != nil {
		log.Fatal(err)
	}
}
```

### Buffered access (`LoadPackets`)

For indexed, random access — pyshark's `keep_packets` behaviour. Pass `0` to load every packet, or a positive count to cap it.

```go
cap, _ := capture.NewFileCapture("capture.pcap")

packets, err := cap.LoadPackets(context.Background(), 0) // 0 = all packets
if err != nil {
	log.Fatal(err)
}

fmt.Printf("loaded %d packets\n", cap.Len())
first := cap.Get(0)
fmt.Println("first packet highest layer:", first.HighestLayer())
_ = packets // cap.Packets() returns the same slice
```

`ApplyOnPacketsWithLimit` adds pyshark's `packet_count` and `timeout` limits:

```go
cap.ApplyOnPacketsWithLimit(func(p *packet.Packet) bool {
	fmt.Println(p.HighestLayer())
	return false
}, context.Background(), 100 /* packet_count */, 5*time.Second /* timeout */)
```

### Live capture

Live capture reads from one or more interfaces and usually requires elevated privileges (e.g. `sudo`).

```go
cap, err := capture.NewLiveCapture([]string{"en0"},
	capture.WithBPFFilter("tcp port 80"),
	capture.WithPacketCount(10),
)
if err != nil {
	log.Fatal(err)
}

err = cap.ApplyOnPackets(func(p *packet.Packet) bool {
	fmt.Println(p.HighestLayer())
	return false
}, context.Background())
```

### Layers and fields

Layers are exposed in protocol order. Field lookup is prefix-aware — on a `tcp` layer, `Field("srcport")` resolves `tcp.srcport`.

```go
cap.ApplyOnPackets(func(p *packet.Packet) bool {
	if ip := p.Layer("ip"); ip != nil {
		fmt.Printf("%v -> %v\n", ip.Field("src"), ip.Field("dst"))
	}
	if tcp := p.Layer("tcp"); tcp != nil {
		fmt.Println("src port:", tcp.Field("srcport"))         // short name
		fmt.Println("dst port:", tcp.GetField("tcp.dstport"))  // fully-qualified name
	}
	fmt.Print(p.String()) // pretty-print every layer and field
	return false
}, context.Background())
```

### In-memory packet parsing

```go
cap := capture.NewInMemCapture(capture.WithLinkType(capture.LinkTypeEthernet))
defer cap.Close()

pkt, err := cap.ParsePacket(rawPacketBytes, nil)
if err != nil {
	log.Fatal(err)
}
fmt.Println(pkt.HighestLayer())
```

### Output modes

GoShark defaults to TShark's JSON output. Select PDML (XML) or EK explicitly:

```go
capture.NewFileCapture("capture.pcap", capture.WithUseJSON(false)) // PDML/XML
capture.NewFileCapture("capture.pcap", capture.WithUseEK(true))    // Elastic Common Schema
```

### Session tracking

```go
tracker := packet.NewSessionTracker()

cap, _ := capture.NewFileCapture("capture.pcap")
cap.ApplyOnPackets(func(p *packet.Packet) bool {
	tracker.AddPacket(p)
	return false
}, context.Background())

for i, s := range tracker.GetAllSessions() {
	fmt.Printf("Session %d: %s — %d packets, state %s\n",
		i+1, s.Key.String(), s.GetPacketCount(), s.State)
}
```

### Raw packet data

When the underlying TShark output carries raw bytes, packets expose them:

```go
raw := p.GetRawPacket()                       // whole frame
ethBytes := p.GetLayerRawBytes("eth")          // one layer's bytes
ipSrc := p.GetFieldRawBytes("ip", "ip.src")    // one field's bytes
```

## Running the Example

`main.go` reads the bundled `test.pcap` and prints a summary of each packet:

```bash
go run .
```

## Testing

```bash
go test ./...
```

The suite includes integration tests that run real TShark against the bundled `test.pcap` for the file, in-memory, pipe, and EK capture paths. These tests skip cleanly when TShark is not installed.

## Documentation

The design spec and implementation plan for the pyshark-parity work live under [`docs/superpowers`](docs/superpowers).

## Author

Vlad Bordei — [github.com/p-vbordei](https://github.com/p-vbordei)

## License

MIT License
