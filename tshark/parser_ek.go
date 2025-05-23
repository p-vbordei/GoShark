package tshark

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"GoShark/packet"
)

// EKParser handles parsing of TShark Elastic Common Schema (EK) output.
type EKParser struct {
	// Configuration options
	IncludeRaw bool
}

// NewEKParser creates a new EKParser instance.
func NewEKParser(options ...func(*EKParser)) *EKParser {
	parser := &EKParser{
		IncludeRaw: false,
	}

	for _, option := range options {
		option(parser)
	}

	return parser
}

// WithEKIncludeRaw sets whether to include raw packet data in the parsed output.
func WithEKIncludeRaw(includeRaw bool) func(*EKParser) {
	return func(p *EKParser) {
		p.IncludeRaw = includeRaw
	}
}

// EKDocument represents a single document in TShark's EK output.
type EKDocument struct {
	Index  EKIndex  `json:"_index"`
	Source EKSource `json:"_source"`
}

// EKIndex contains index information for an EK document.
type EKIndex struct {
	Type string `json:"_type"`
}

// EKSource contains the packet data in an EK document.
type EKSource struct {
	Layers    map[string]json.RawMessage `json:"layers"`
	Timestamp time.Time                  `json:"timestamp"`
}

// ParsePackets reads TShark EK output from the provided reader and returns a slice of Packet objects.
func (p *EKParser) ParsePackets(r io.Reader) ([]*packet.Packet, error) {
	// Create a JSON decoder for streaming JSON parsing
	decoder := json.NewDecoder(r)

	// Read documents from the stream
	var documents []EKDocument
	for decoder.More() {
		var doc EKDocument
		if err := decoder.Decode(&doc); err != nil {
			return nil, fmt.Errorf("failed to decode EK document: %w", err)
		}
		documents = append(documents, doc)
	}

	// Convert documents to packets
	packets := make([]*packet.Packet, 0, len(documents))
	for _, doc := range documents {
		pkt, err := p.convertEKDocument(&doc)
		if err != nil {
			return nil, fmt.Errorf("failed to convert EK document: %w", err)
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}

// convertEKDocument converts an EKDocument to a Packet.
func (p *EKParser) convertEKDocument(doc *EKDocument) (*packet.Packet, error) {
	// Create a new Packet
	pkt := &packet.Packet{}

	// Set timestamp from EK document
	pkt.FrameTime = doc.Source.Timestamp.Format(time.RFC3339)
	
	// Extract frame information if available
	if frameData, ok := doc.Source.Layers["frame"]; ok {
		var frameLayer map[string]interface{}
		if err := json.Unmarshal(frameData, &frameLayer); err != nil {
			return nil, fmt.Errorf("failed to unmarshal frame layer: %w", err)
		}
		
		// Extract frame number
		if frameNum, ok := frameLayer["frame.number"].(string); ok {
			pkt.FrameNumber = frameNum
		}
		
		// Extract frame length
		if frameLen, ok := frameLayer["frame.len"].(string); ok {
			pkt.FrameLen = frameLen
		}
		
		// Extract capture length
		if frameCapLen, ok := frameLayer["frame.cap_len"].(string); ok {
			pkt.FrameCapLen = frameCapLen
		}
		
		// Extract epoch time
		if frameTimeEpoch, ok := frameLayer["frame.time_epoch"].(string); ok {
			pkt.FrameTimeEpoch = frameTimeEpoch
		}
	}

	// Convert layers
	pkt.Layers = make([]packet.Layer, 0, len(doc.Source.Layers))
	for layerName, layerData := range doc.Source.Layers {
		layer, err := p.convertEKLayer(layerName, layerData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert layer %s: %w", layerName, err)
		}
		pkt.Layers = append(pkt.Layers, *layer)
	}

	return pkt, nil
}

// convertEKLayer converts a layer from EK format to a Layer.
func (p *EKParser) convertEKLayer(layerName string, layerData json.RawMessage) (*packet.Layer, error) {
	// Create a new Layer
	layer := &packet.Layer{
		Name:   layerName,
		Fields: make(map[string]interface{}),
	}

	// Unmarshal the layer data
	var fields map[string]interface{}
	if err := json.Unmarshal(layerData, &fields); err != nil {
		return nil, fmt.Errorf("failed to unmarshal layer data: %w", err)
	}

	// Add fields to the layer
	for fieldName, fieldValue := range fields {
		// Handle nested fields
		if nestedMap, ok := fieldValue.(map[string]interface{}); ok {
			// Create a nested layer
			nestedLayer := &packet.Layer{
				Name:   fmt.Sprintf("%s.%s", layerName, fieldName),
				Fields: nestedMap,
			}
			
			// Add the nested layer to the fields
			layer.Fields[fieldName] = nestedLayer
		} else {
			// Add the field directly
			layer.Fields[fieldName] = fieldValue
		}
	}

	return layer, nil
}

// ParseSinglePacket parses a single packet from an EK JSON string.
func (p *EKParser) ParseSinglePacket(jsonData string) (*packet.Packet, error) {
	// Parse as EK document
	var doc EKDocument
	if err := json.Unmarshal([]byte(jsonData), &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal EK document: %w", err)
	}

	// Convert to packet
	return p.convertEKDocument(&doc)
}

// ParseTSharkEK is a convenience function that creates an EKParser and parses packets from a reader.
func ParseTSharkEK(r io.Reader, includeRaw bool) ([]*packet.Packet, error) {
	parser := NewEKParser(WithEKIncludeRaw(includeRaw))
	return parser.ParsePackets(r)
}

// ParseTSharkEKString is a convenience function that creates an EKParser and parses packets from a string.
func ParseTSharkEKString(jsonData string, includeRaw bool) ([]*packet.Packet, error) {
	parser := NewEKParser(WithEKIncludeRaw(includeRaw))
	return parser.ParsePackets(strings.NewReader(jsonData))
}
