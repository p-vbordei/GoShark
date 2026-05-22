package capture_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/p-vbordei/GoShark/capture"
	"github.com/p-vbordei/GoShark/tests"
)

func TestInMemCapture(t *testing.T) {
	tests.SkipIfNoTShark(t)

	// Create a new in-memory capture
	cap := capture.NewInMemCapture(
		capture.WithDisplayFilter("tcp"),
	)

	// Test parsing a packet with Ethernet header
	packetData := []byte{
		// Ethernet Header
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
		0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // Src MAC
		0x08, 0x00,                         // Type: IPv4
		// IPv4 Header
		0x45, 0x00, 0x00, 0x3c, 0x7c, 0x3c, 0x40, 0x00, 0x40, 0x06, 0x65, 0x7a, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01,
		// TCP Header
		0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xbd, 0x86, 0x00, 0x00,
	}

	// Parse a single packet with current time
	sniffTime := time.Now()
	packet, err := cap.ParsePacket(packetData, &sniffTime)
	if err != nil {
		t.Fatalf("Could not parse packet: %v", err)
	}

	assert.NotNil(t, packet, "Parsed packet should not be nil")

	// Test parsing multiple packets
	packets, err := cap.ParsePackets([][]byte{packetData}, []*time.Time{&sniffTime})
	if err != nil {
		t.Fatalf("Could not parse packets: %v", err)
	}

	assert.Equal(t, 1, len(packets), "Should have parsed 1 packet")
}

func TestInMemCaptureWithOutputFile(t *testing.T) {
	tests.SkipIfNoTShark(t)

	// Create a temporary output file
	tmpFile := t.TempDir() + "/test_output.pcap"

	// Create a new in-memory capture with output file
	cap := capture.NewInMemCapture(
		capture.WithOutputFile(tmpFile),
	)

	// Create test packet data with Ethernet header
	packetData := []byte{
		// Ethernet Header
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
		0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // Src MAC
		0x08, 0x00,                         // Type: IPv4
		// IPv4 Header
		0x45, 0x00, 0x00, 0x3c, 0x7c, 0x3c, 0x40, 0x00, 0x40, 0x06, 0x65, 0x7a, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01,
		// TCP Header
		0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xbd, 0x86, 0x00, 0x00,
	}
	sniffTime := time.Now()

	// Parse packets which should write to the output file
	packets, err := cap.ParsePackets([][]byte{packetData}, []*time.Time{&sniffTime})
	if err != nil {
		t.Fatalf("Could not parse packets: %v", err)
	}

	assert.Equal(t, 1, len(packets), "Should have parsed 1 packet")

	// Verify the output file exists
	_, err = os.Stat(tmpFile)
	assert.NoError(t, err, "Output file should exist")
}
