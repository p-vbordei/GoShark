package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"GoShark/packet"
	"GoShark/tshark"
)

// LinkType represents the link layer type of a packet.
type LinkType int

// Define common LinkType constants mirroring pyshark's LinkTypes.
const (
	LinkTypeNull     LinkType = 0
	LinkTypeEthernet LinkType = 1
	LinkTypeIEEE802_5 LinkType = 6
	LinkTypePPP      LinkType = 9
	LinkTypeIEEE802_11 LinkType = 105
)

// InMemCapture represents a packet capture from in-memory binary data.
type InMemCapture struct {
	Capture
	currentLinkType LinkType
	currentTShark   struct {
		Process io.ReadCloser
		Stderr  io.ReadCloser
		Stdin   io.WriteCloser
	}
	packets         []*packet.Packet
	pcapHeaderWritten bool
}

// NewInMemCapture creates a new InMemCapture instance.
func NewInMemCapture(options ...func(*Capture)) *InMemCapture {
	c := &InMemCapture{
		Capture: Capture{
			UseJSON: true,
		},
		currentLinkType: LinkTypeEthernet,
		packets:         make([]*packet.Packet, 0),
		pcapHeaderWritten: false,
	}

	for _, option := range options {
		option(&c.Capture)
	}

	return c
}

// WithLinkType sets the link type for the in-memory capture.
func WithLinkType(linkType LinkType) func(*Capture) {
	return func(c *Capture) {
		// This is a bit of a hack, but we need to cast the Capture to an InMemCapture
		// to set the link type. This will only work if the Capture is actually an InMemCapture.
		if inMem, ok := interface{}(c).(*InMemCapture); ok {
			inMem.currentLinkType = linkType
		}
	}
}

// getTSharkProcess gets or creates a TShark process for parsing packets.
func (c *InMemCapture) getTSharkProcess() error {
	if c.currentTShark.Process != nil {
		return nil
	}

	// Set up command line arguments for reading from stdin and outputting JSON
	args := []string{"--enable-heuristic", "ssl", "-i", "-", "-o", "tcp.relative_sequence_numbers:FALSE", "-Tjson"}

	// Create the command
	cmd, err := tshark.RunTSharkCommand(c.TSharkPath, args...)
	if err != nil {
		return fmt.Errorf("error creating tshark command: %w", err)
	}

	c.cmd = cmd // Store the command for later use (e.g., closing pipes)

	// Get stdout, stderr, and stdin pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error getting stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error getting stderr pipe: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("error getting stdin pipe: %w", err)
	}

	// Start the TShark process
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting tshark process: %w", err)
	}

	// Store the process outputs and input
	c.currentTShark.Process = stdout
	c.currentTShark.Stderr = stderr
	c.currentTShark.Stdin = stdin

	return nil
}

// writePCAPHeader writes a PCAP file header to the given writer.
func (c *InMemCapture) writePCAPHeader(writer io.Writer) error {
	// PCAP header format: magic number, version major, version minor, 
	// timezone offset, timestamp accuracy, snapshot length, link type
	header := struct {
		MagicNumber  uint32 // 0xa1b2c3d4
		VersionMajor uint16 // 2
		VersionMinor uint16 // 4
		TimezoneOffset uint32 // 0
		TimestampAccuracy uint32 // 0
		SnapshotLength uint32 // 0x7fff (32767)
		LinkType     uint32 // Ethernet, etc.
	}{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		TimezoneOffset: 0,
		TimestampAccuracy: 0,
		SnapshotLength: 0x7fff,
		LinkType:     uint32(c.currentLinkType),
	}

	err := binary.Write(writer, binary.LittleEndian, header)
	if err != nil {
		return fmt.Errorf("error writing PCAP header: %w", err)
	}

	return nil
}

// writePacket writes a single packet with its header to the TShark process.
func (c *InMemCapture) writePacket(packet []byte, sniffTime *time.Time) error {
	if c.currentTShark.Stdin == nil {
		return fmt.Errorf("tshark stdin not initialized")
	}

	// Packet header (16 bytes)
	// typedef struct pcaprec_hdr_s {
	//     guint32 ts_sec;     /* timestamp seconds */
	//     guint32 ts_usec;    /* timestamp microseconds */
	//     guint32 incl_len;   /* number of octets of packet saved in file */
	//     guint32 orig_len;   /* actual length of packet */
	// } pcaprec_hdr_t;

	// Use current time if sniffTime is not provided
	if sniffTime == nil {
		now := time.Now()
		sniffTime = &now
	}

	// Create packet header
	packetHeader := new(bytes.Buffer)
	err := binary.Write(packetHeader, binary.LittleEndian, uint32(sniffTime.Unix()))
	if err != nil {
		return fmt.Errorf("error writing timestamp seconds: %w", err)
	}
	err = binary.Write(packetHeader, binary.LittleEndian, uint32(sniffTime.Nanosecond()/1000))
	if err != nil {
		return fmt.Errorf("error writing timestamp microseconds: %w", err)
	}
	err = binary.Write(packetHeader, binary.LittleEndian, uint32(len(packet)))
	if err != nil {
		return fmt.Errorf("error writing included length: %w", err)
	}
	err = binary.Write(packetHeader, binary.LittleEndian, uint32(len(packet)))
	if err != nil {
		return fmt.Errorf("error writing original length: %w", err)
	}

	// Write packet header and data to TShark's stdin
	_, err = c.currentTShark.Stdin.Write(packetHeader.Bytes())
	if err != nil {
		return fmt.Errorf("error writing packet header to stdin: %w", err)
	}
	_, err = c.currentTShark.Stdin.Write(packet)
	if err != nil {
		return fmt.Errorf("error writing packet data to stdin: %w", err)
	}

	return nil
}

// writePacketToTSharkStdin writes a single packet with its header to the TShark process's stdin.
func (c *InMemCapture) writePacketToTSharkStdin(packet []byte, sniffTime *time.Time) error {
	// Write PCAP header if not already written
	if c.currentTShark.Stdin == nil {
		return fmt.Errorf("tshark stdin not initialized")
	}

	// Write PCAP header only once
	if !c.pcapHeaderWritten {
		err := c.writePCAPHeader(c.currentTShark.Stdin)
		if err != nil {
			return fmt.Errorf("error writing pcap header: %w", err)
		}
		c.pcapHeaderWritten = true
	}

	return c.writePacket(packet, sniffTime)
}

// Close closes the TShark process and cleans up resources.
func (c *InMemCapture) Close() error {
	if c.currentTShark.Process != nil {
		c.currentTShark.Stdin.Close()
		c.cmd.Process.Kill()
		c.currentTShark.Process = nil
		c.currentTShark.Stderr = nil
		c.currentTShark.Stdin = nil
	}
	return nil
}

// ParsePacket parses a single raw binary packet and returns a Packet.
// It writes the binary data to a pipe and uses tshark to read from it.
func (c *InMemCapture) ParsePacket(binaryPacket []byte, sniffTime *time.Time) (*packet.Packet, error) {
	err := c.getTSharkProcess()
	if err != nil {
		return nil, err
	}

	// Write the packet to TShark's stdin
	err = c.writePacketToTSharkStdin(binaryPacket, sniffTime)
	if err != nil {
		return nil, fmt.Errorf("error writing packet to tshark stdin: %w", err)
	}

	packets, err := c.readPacketsFromTShark(1)
	if err != nil {
		return nil, err
	}

	if len(packets) == 0 {
		return nil, fmt.Errorf("no packet parsed")
	}

	return packets[0], nil
}

// ParsePackets parses multiple raw binary packets and returns a slice of Packets.
// This is more efficient than parsing packets one by one.
func (c *InMemCapture) ParsePackets(binaryPackets [][]byte, sniffTimes []*time.Time) ([]*packet.Packet, error) {
	err := c.getTSharkProcess()
	if err != nil {
		return nil, err
	}

	// Write all packets to TShark's stdin
	for i, binaryPacket := range binaryPackets {
		var sniffTime *time.Time
		if sniffTimes != nil && i < len(sniffTimes) {
			sniffTime = sniffTimes[i]
		}
		err = c.writePacketToTSharkStdin(binaryPacket, sniffTime)
		if err != nil {
			return nil, fmt.Errorf("error writing packet %d to tshark stdin: %w", i, err)
		}
	}

	return c.readPacketsFromTShark(len(binaryPackets))
}

// readPacketsFromTShark reads and parses packets from the TShark process.
func (c *InMemCapture) readPacketsFromTShark(expectedCount int) ([]*packet.Packet, error) {
	if c.currentTShark.Process == nil {
		return nil, fmt.Errorf("TShark process not initialized")
	}

	// Read output from TShark
	var outputBuffer bytes.Buffer
	_, err := io.Copy(&outputBuffer, c.currentTShark.Process)
	if err != nil {
		return nil, fmt.Errorf("error reading TShark output: %w", err)
	}

	// Check for errors from TShark
	var stderrBuffer bytes.Buffer
	_, err = io.Copy(&stderrBuffer, c.currentTShark.Stderr)
	if err != nil {
		return nil, fmt.Errorf("error reading TShark stderr: %w", err)
	}

	if stderrBuffer.Len() > 0 {
		return nil, fmt.Errorf("TShark error: %s", stderrBuffer.String())
	}

	// Parse the output into packets
	packets, err := packet.ParsePackets(outputBuffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error parsing packet JSON: %w", err)
	}

	// Verify we got the expected number of packets
	if len(packets) != expectedCount {
		return packets, fmt.Errorf("expected %d packets but got %d", expectedCount, len(packets))
	}

	return packets, nil
}

// FeedPacket adds a single packet to the capture and returns the parsed packet.
// This is a convenience method that parses the packet and adds it to the internal packet list.
// It's equivalent to the deprecated feed_packet method in the Python implementation.
func (c *InMemCapture) FeedPacket(binaryPacket []byte, linkType LinkType, sniffTime *time.Time) (*packet.Packet, error) {
	c.currentLinkType = linkType
	pkt, err := c.ParsePacket(binaryPacket, sniffTime)
	if err != nil {
		return nil, err
	}
	c.Close()
	c.packets = append(c.packets, pkt)
	return pkt, nil
}

// FeedPackets adds multiple packets to the capture and returns the parsed packets.
// This is a convenience method that parses the packets and adds them to the internal packet list.
func (c *InMemCapture) FeedPackets(binaryPackets [][]byte, linkType LinkType, sniffTimes []*time.Time) ([]*packet.Packet, error) {
	c.currentLinkType = linkType
	parsedPackets, err := c.ParsePackets(binaryPackets, sniffTimes)
	if err != nil {
		return nil, err
	}
	c.Close()
	c.packets = append(c.packets, parsedPackets...)
	return parsedPackets, nil
}
