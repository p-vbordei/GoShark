package capture

import (
	"bytes"
	"fmt"
	"io"

	"GoShark/goshark/packet"
	"GoShark/goshark/tshark"
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
}

// NewInMemCapture creates a new InMemCapture instance.
func NewInMemCapture(options ...Option) *InMemCapture {
	c := &InMemCapture{
		Capture: Capture{
			TShark: tshark.NewTShark(),
		},
	}

	for _, option := range options {
		option(&c.Capture)
	}

	return c
}

// ParsePacket parses a single raw binary packet and returns a Packet.
// It writes the binary data to a pipe and uses tshark to read from it.
func (c *InMemCapture) ParsePacket(binaryPacket []byte, linkType LinkType) (*packet.Packet, error) {
	reader, writer := io.Pipe()

	go func() {
		defer writer.Close()
		_, err := writer.Write(binaryPacket)
		if err != nil {
			fmt.Printf("Error writing to pipe: %v\n", err)
		}
	}()

	c.Capture.SetCommandLineArgs("-r", "-", "-L", fmt.Sprintf("%d", linkType)) // Read from stdin with specified link type

	stdout, stderr, err := c.Capture.Start(reader)
	if err != nil {
		return nil, fmt.Errorf("error starting tshark for in-memory capture: %w", err)
	}

	// Read output from stdout and parse the packet
	var outputBuffer bytes.Buffer
	_, err = io.Copy(&outputBuffer, stdout)
	if err != nil {
		return nil, fmt.Errorf("error reading tshark stdout: %w", err)
	}

	// Check for stderr output for potential tshark errors
	var stderrBuffer bytes.Buffer
	_, err = io.Copy(&stderrBuffer, stderr)
	if err != nil {
		return nil, fmt.Errorf("error reading tshark stderr: %w", err)
	}

	if stderrBuffer.Len() > 0 {
		return nil, fmt.Errorf("tshark error: %s", stderrBuffer.String())
	}

	// Assuming tshark outputs JSON for a single packet
	p, err := packet.NewPacketFromJSON(outputBuffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error parsing packet JSON: %w", err)
	}

	// Stop the capture after parsing the single packet
	c.Capture.Stop() // Ensure tshark process is terminated

	return p, nil
}
