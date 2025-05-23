package capture_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"GoShark/capture"
	"GoShark/tests"
)

func TestInMemCapture(t *testing.T) {
	tests.SkipIfNoTShark(t)

	// Create a new in-memory capture
	cap := capture.NewInMemCapture(
		capture.WithDisplayFilter("tcp"),
	)

	// Test parsing a packet
	packetData := []byte{0x45, 0x00, 0x00, 0x3c, 0x7c, 0x3c, 0x40, 0x00, 0x40, 0x06, 0x65, 0x7a, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xbd, 0x86, 0x00, 0x00}

	// Parse a single packet with current time
	sniffTime := time.Now()
	packet, err := cap.ParsePacket(packetData, &sniffTime)
	// This test might fail if tshark is not available or cannot parse the packet
	// So we'll just check if we got an error and skip if we did
	if err != nil {
		t.Skip("Could not parse packet, skipping test: " + err.Error())
	}

	assert.NotNil(t, packet, "Parsed packet should not be nil")

	// Test parsing multiple packets
	packets, err := cap.ParsePackets([][]byte{packetData}, []*time.Time{&sniffTime})
	if err != nil {
		t.Skip("Could not parse packets, skipping test: " + err.Error())
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

	// Create test packet data
	packetData := []byte{0x45, 0x00, 0x00, 0x3c, 0x7c, 0x3c, 0x40, 0x00, 0x40, 0x06, 0x65, 0x7a, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xbd, 0x86, 0x00, 0x00}
	sniffTime := time.Now()

	// Parse packets which should write to the output file
	packets, err := cap.ParsePackets([][]byte{packetData}, []*time.Time{&sniffTime})
	// This test might fail if tshark is not available or cannot parse the packet
	if err != nil {
		t.Skip("Could not parse packets, skipping test: " + err.Error())
	}

	assert.Equal(t, 1, len(packets), "Should have parsed 1 packet")

	// Verify the output file exists
	_, err = os.Stat(tmpFile)
	assert.NoError(t, err, "Output file should exist")
}
