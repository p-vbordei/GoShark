# GoShark

GoShark is a Go implementation of the Python `pyshark` library, providing a powerful interface to TShark (the command-line version of Wireshark) for packet capture and analysis in Go applications. It leverages `tshark` for packet capture and analysis, similar to how `pyshark` operates.

## Features

- **Multiple Capture Types**: Support for live captures, file captures, remote captures, pipe captures, and in-memory captures
- **Flexible Filtering**: Apply display filters (Wireshark syntax) and capture filters (BPF syntax)
- **JSON/XML/EK Output**: Parse TShark output in JSON, XML (PDML), or Elastic Common Schema formats
- **Layer Access**: Easy access to packet layers and fields with a clean API
- **Raw Packet Data**: Access to raw packet bytes, field offsets, and values in different bases
- **Session Tracking**: Track network sessions and conversations across multiple packets
- **PCAP Export**: Write captured packets to PCAP files
- **Configuration Management**: Load and save settings from configuration files
- **Caching**: Cache TShark output for improved performance
- **Comprehensive Tests**: Extensive test suite covering all major functionality

## Installation

```bash
go install github.com/vladbordei/GoShark@latest
```

## Requirements

- Go 1.16 or higher
- Wireshark/TShark installed and available in your system's PATH

## Environmental Variables

- `TSHARK_PATH`: (Optional) Specifies a custom path for the TShark executable. If not set, GoShark will attempt to find TShark in your system's PATH.
- `DUMPCAP_PATH`: (Optional) Specifies a custom path for the dumpcap executable (used for live captures). If not set, GoShark will attempt to find dumpcap in your system's PATH.
- `GO_SHARK_CACHE_DIR`: (Optional) Override default cache directory. If not set, GoShark will default to platform-specific cache paths.
- `GO_SHARK_CONFIG_DIR`: (Optional) Override default config directory. If not set, GoShark will default to platform-specific config paths.

## Project Structure

GoShark is organized into several key directories, each responsible for a specific aspect of the library:

- `capture`: Contains implementations for various packet capture types (live, file, in-memory, etc.).
- `packet`: Defines the `Packet` structure and related functionalities for parsing and accessing packet data.
- `tshark`: Handles the execution of TShark commands and manages TShark-related configurations.
- `utils`: Provides utility functions used across the project.
- `tests`: Contains comprehensive tests for all major functionalities.

## Dependencies and APIs

GoShark leverages the following Go packages and external tools:

- `os/exec`: Used for executing external commands, primarily `tshark`.
- `golang.org/x/mod/semver`: Utilized for semantic versioning comparisons of TShark.
- **TShark**: The core dependency, providing packet capture and analysis capabilities. GoShark acts as a wrapper around the TShark command-line tool.

## Comprehensive Test Suite

GoShark includes an extensive test suite to ensure the reliability and correctness of its functionalities. Tests cover:

- Packet handling and parsing.
- Various capture types (live, file, in-memory).
- TShark command execution and output processing.

To run the tests, navigate to the project root and execute:

```bash
go test ./...
```

## Basic Usage

### Live Capture Example

```go
package main

import (
	"fmt"
	"GoShark/capture"
)

func main() {
	// Create a new live capture on interface "eth0"
	cap := capture.NewLiveCapture(
		capture.WithInterface("eth0"),
		capture.WithDisplayFilter("http"),
		capture.WithPacketCount(10),
	)

	// Start the capture
	packets, err := cap.Capture()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Process captured packets
	for _, packet := range packets {
		fmt.Printf("Packet: %s\n", packet.SniffTime())
		
		// Access HTTP layer if present
		if httpLayer := packet.GetLayer("http"); httpLayer != nil {
			host := httpLayer.GetField("host")
			if host != nil {
				fmt.Printf("HTTP Host: %s\n", host)
			}
		}
	}
}
```

### File Capture Example

```go
package main

import (
	"fmt"
	"GoShark/capture"
)

func main() {
	// Create a new file capture
	cap := capture.NewFileCapture(
		capture.WithInputFile("path/to/capture.pcap"),
		capture.WithDisplayFilter("tcp"),
	)

	// Start the capture
	packets, err := cap.Capture()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Process captured packets
	for _, packet := range packets {
		fmt.Printf("Packet #%s: %s\n", packet.FrameNumber, packet.SniffTime())
	}
}
```

### In-Memory Packet Processing

```go
package main

import (
    "fmt"
    "io/ioutil"
    "strings"
    "GoShark/capture"
)

func main() {
    // Read raw packet data from a file
    rawPacket, err := ioutil.ReadFile("raw_packet.bin")
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        return
    }

    // Create an in-memory capture
    cap := capture.NewInMemCapture()

    // Parse the raw packet
    pkt, err := cap.ParsePacket(rawPacket, nil)
    if err != nil {
        // Skip if TShark isn't available or stdin not initialized
        if strings.Contains(err.Error(), "tshark stdin not initialized") {
            fmt.Println("Skipping in-memory packet processing: TShark not found or not initialized")
            return
        }
        fmt.Printf("Error parsing packet: %v\n", err)
        return
    }

    // Display parsed packet
    fmt.Printf("Parsed packet: %+v\n", pkt)
}
```

### Session Tracking

```go
package main

import (
	"fmt"
	"GoShark/capture"
	"GoShark/packet"
)

func main() {
	// Create a live capture
	cap := capture.NewLiveCapture(
		capture.WithInterface("eth0"),
		capture.WithDisplayFilter("tcp"),
	)

	// Create a session tracker
	tracker := packet.NewSessionTracker()

	// Start capturing packets
	packets, err := cap.Capture()
	if err != nil {
		fmt.Printf("Error capturing packets: %v\n", err)
		return
	}

	// Add packets to the session tracker
	for _, p := range packets {
		tracker.AddPacket(p)
	}

	// Get all sessions
	sessions := tracker.GetAllSessions()
	
	// Print session information
	for i, session := range sessions {
		fmt.Printf("Session %d: %s\n", i+1, session.Key.String())
		fmt.Printf("  Packets: %d\n", session.GetPacketCount())
		fmt.Printf("  State: %s\n", session.State)
		fmt.Printf("  Duration: %d seconds\n", session.GetDuration())
	}
}
```

### Raw Packet Data Access

```go
package main

import (
	"fmt"
	"encoding/hex"
	"GoShark/capture"
)

func main() {
	// Create a file capture
	cap := capture.NewFileCapture(
		capture.WithInputFile("sample.pcap"),
	)

	// Capture packets
	packets, err := cap.Capture()
	if err != nil {
		fmt.Printf("Error capturing packets: %v\n", err)
		return
	}

	if len(packets) > 0 {
		// Get the first packet
		p := packets[0]

		// Get raw packet data
		rawData := p.GetRawPacket()
		fmt.Printf("Raw packet data: %s\n", hex.EncodeToString(rawData))

		// Get a specific layer's raw bytes
		ethLayer := p.GetLayerRawBytes("eth")
		if ethLayer != nil {
			fmt.Printf("Ethernet layer data: %s\n", hex.EncodeToString(ethLayer))
		}

		// Get a specific field's raw bytes
		ipSrc := p.GetFieldRawBytes("ip", "ip.src")
		if ipSrc != nil {
			fmt.Printf("IP source address raw bytes: %s\n", hex.EncodeToString(ipSrc))
		}
	}
}
```

## Running the Example Application

To run the example application, ensure you have TShark installed and available in your system's PATH.

```bash
go run main.go
```

**Note**: For testing purposes, `main.go` is configured to capture a limited number of packets (currently 10) to prevent an infinite capture loop. You can modify this limit in `main.go` or extend the `capture` package to support other capture termination conditions.

## Current Status

The project has implemented most of the core functionality of the Python `pyshark` library, including:

- ✅ All capture types (live, file, remote, pipe, in-memory)
- ✅ JSON, XML, and EK output parsing
- ✅ Layer and field access
- ✅ Display and capture filtering
- ✅ PCAP export
- ✅ Configuration management
- ✅ Cache management
- ✅ Packet dissection details (raw bytes, field offsets)
- ✅ Session/conversation tracking
- ✅ Comprehensive test suite

Upcoming features:

- 🔄 Protocol-specific parsers

## Detailed Progress

See `progress.md` for detailed updates on implementation status.

## Lessons Learned

See `lessons_learned.md` for insights and challenges encountered during development.

## License

MIT License
