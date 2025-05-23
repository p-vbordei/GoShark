package tshark

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"GoShark/packet"
)

// JSONParser handles parsing of TShark JSON output.
type JSONParser struct {
	// Configuration options could be added here
	IncludeRaw bool
}

// NewJSONParser creates a new JSONParser instance.
func NewJSONParser(options ...func(*JSONParser)) *JSONParser {
	parser := &JSONParser{
		IncludeRaw: false,
	}

	for _, option := range options {
		option(parser)
	}

	return parser
}

// WithIncludeRaw sets whether to include raw packet data in the parsed output.
func WithIncludeRaw(includeRaw bool) func(*JSONParser) {
	return func(p *JSONParser) {
		p.IncludeRaw = includeRaw
	}
}

// ParsePackets reads TShark JSON output from the provided reader and returns a slice of Packet objects.
func (p *JSONParser) ParsePackets(r io.Reader) ([]*packet.Packet, error) {
	// Create a JSON decoder for streaming JSON parsing
	decoder := json.NewDecoder(r)

	// Check for the start of the JSON array
	t, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON token: %w", err)
	}

	// Ensure we have a JSON array
	delim, ok := t.(json.Delim)
	if !ok || delim != '[' {
		return nil, fmt.Errorf("expected JSON array, got %v", t)
	}

	var packets []*packet.Packet

	// Read each packet from the array
	for decoder.More() {
		var pkt packet.Packet
		if err := decoder.Decode(&pkt); err != nil {
			return nil, fmt.Errorf("failed to decode packet: %w", err)
		}
		packets = append(packets, &pkt)
	}

	// Check for the end of the JSON array
	t, err = decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to read closing JSON token: %w", err)
	}

	delim, ok = t.(json.Delim)
	if !ok || delim != ']' {
		return nil, fmt.Errorf("expected end of JSON array, got %v", t)
	}

	return packets, nil
}

// ParseSinglePacket parses a single packet from a JSON string.
func (p *JSONParser) ParseSinglePacket(jsonData string) (*packet.Packet, error) {
	// Check if the JSON is an array with a single packet
	jsonData = strings.TrimSpace(jsonData)
	if strings.HasPrefix(jsonData, "[") && strings.HasSuffix(jsonData, "]") {
		// Parse as array and return the first packet
		packets, err := p.ParsePackets(strings.NewReader(jsonData))
		if err != nil {
			return nil, err
		}
		if len(packets) == 0 {
			return nil, fmt.Errorf("no packets found in JSON array")
		}
		return packets[0], nil
	}

	// Parse as a single JSON object
	var pkt packet.Packet
	if err := json.Unmarshal([]byte(jsonData), &pkt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal packet: %w", err)
	}

	return &pkt, nil
}

// ParseLayerJSON parses a JSON layer object into a Layer struct.
func (p *JSONParser) ParseLayerJSON(layerJSON json.RawMessage, layerName string) (*packet.Layer, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal(layerJSON, &fields); err != nil {
		return nil, fmt.Errorf("failed to unmarshal layer %s: %w", layerName, err)
	}

	layer := &packet.Layer{
		Name:   layerName,
		Fields: fields,
	}

	return layer, nil
}

// HandleNestedLayers processes nested layers within a parent layer.
func (p *JSONParser) HandleNestedLayers(parentLayer *packet.Layer) error {
	// Look for fields that might be nested layers
	for fieldName, fieldValue := range parentLayer.Fields {
		// Check if the field is a map, which might indicate a nested layer
		if nestedMap, ok := fieldValue.(map[string]interface{}); ok {
			// Create a new layer for the nested structure
			nestedLayer := &packet.Layer{
				Name:   fmt.Sprintf("%s.%s", parentLayer.Name, fieldName),
				Fields: nestedMap,
			}

			// Recursively handle any further nesting
			if err := p.HandleNestedLayers(nestedLayer); err != nil {
				return err
			}

			// Replace the map with a reference to the nested layer
			parentLayer.Fields[fieldName] = nestedLayer
		}
	}

	return nil
}

// ParseTSharkJSON is a convenience function that creates a JSONParser and parses packets from a reader.
func ParseTSharkJSON(r io.Reader, includeRaw bool) ([]*packet.Packet, error) {
	parser := NewJSONParser(WithIncludeRaw(includeRaw))
	return parser.ParsePackets(r)
}

// ParseTSharkJSONString is a convenience function that creates a JSONParser and parses packets from a string.
func ParseTSharkJSONString(jsonData string, includeRaw bool) ([]*packet.Packet, error) {
	parser := NewJSONParser(WithIncludeRaw(includeRaw))
	return parser.ParsePackets(strings.NewReader(jsonData))
}
