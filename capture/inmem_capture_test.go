package capture

import (
	"bytes"
	"testing"
	"time"
)

func TestInMemCapture(t *testing.T) {
	// Create a new in-memory capture
	cap := NewInMemCapture()

	// Test default values
	if !cap.UseJSON {
		t.Errorf("Default UseJSON should be true")
	}

	// Create a test packet
	packetData := []byte{0x45, 0x00, 0x00, 0x3c, 0x7c, 0x3c, 0x40, 0x00, 0x40, 0x06, 0x65, 0x7a, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xbd, 0x86, 0x00, 0x00}
	sniffTime := time.Now()

	// Test writing a packet to a buffer
	var buf bytes.Buffer
	err := cap.writePacket(&buf, packetData, &sniffTime)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	// The packet header is 16 bytes, and the packet data is 40 bytes. Total should be 56 bytes.
	if buf.Len() != 56 {
		t.Errorf("Expected buffer length to be 56, got %d", buf.Len())
	}
}

func TestInMemCaptureWithOptions(t *testing.T) {
	// Create a new in-memory capture with options
	cap := NewInMemCapture(
		WithDisplayFilter("tcp"),
		WithUseJSON(false),
		WithLinkType(LinkTypeEthernet),
	)

	// Test option values
	if cap.DisplayFilter != "tcp" {
		t.Errorf("DisplayFilter should be 'tcp', got '%s'", cap.DisplayFilter)
	}

	if cap.UseJSON {
		t.Errorf("UseJSON should be false")
	}

	if cap.currentLinkType != LinkTypeEthernet {
		t.Errorf("LinkType should be LinkTypeEthernet, got %v", cap.currentLinkType)
	}
}
