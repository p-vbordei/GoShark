package packet

import (
	"testing"
)

func TestPacketBasic(t *testing.T) {
	// Create a simple test packet
	p := &Packet{
		RawData: []byte{0x45, 0x00, 0x00, 0x3c},
	}

	// Test GetRawPacket
	rawData := p.GetRawPacket()
	if len(rawData) != 4 {
		t.Errorf("Expected raw data length of 4, got %d", len(rawData))
	}
}
