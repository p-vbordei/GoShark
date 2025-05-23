package packet

import (
	"encoding/json"
	"fmt"
)

// Packet represents a decoded network packet from TShark.
// This struct will need to be refined based on the actual JSON output structure of TShark.
// For now, it's a basic representation.
type Packet struct {
	Source struct {
		Layers map[string]interface{} `json:"layers"`
	} `json:"_source"`
}

// ParsePackets takes raw TShark JSON output (an array of packets) and unmarshals it into a slice of Packet structs.
func ParsePackets(data []byte) ([]*Packet, error) {
	var packets []*Packet
	if err := json.Unmarshal(data, &packets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal packets JSON: %w", err)
	}
	return packets, nil
}

// ParsePacket takes raw TShark JSON output for a single packet and unmarshals it into a Packet struct.
func ParsePacket(data []byte) (*Packet, error) {
	var p Packet
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal single packet JSON: %w", err)
	}
	return &p, nil
}
