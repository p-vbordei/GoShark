package tshark

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"GoShark/packet"
)

// XMLParser handles parsing of TShark PDML (XML) output.
type XMLParser struct {
	// Configuration options could be added here
	IncludeRaw bool
}

// NewXMLParser creates a new XMLParser instance.
func NewXMLParser(options ...func(*XMLParser)) *XMLParser {
	parser := &XMLParser{
		IncludeRaw: false,
	}

	for _, option := range options {
		option(parser)
	}

	return parser
}

// WithXMLIncludeRaw sets whether to include raw packet data in the parsed output.
func WithXMLIncludeRaw(includeRaw bool) func(*XMLParser) {
	return func(p *XMLParser) {
		p.IncludeRaw = includeRaw
	}
}

// PDML represents the root element of TShark's PDML output.
type PDML struct {
	XMLName xml.Name `xml:"pdml"`
	Packets []PDMLPacket `xml:"packet"`
}

// PDMLPacket represents a packet in TShark's PDML output.
type PDMLPacket struct {
	XMLName  xml.Name    `xml:"packet"`
	FrameNum string      `xml:"num,attr"`
	Layers   []PDMLProto `xml:"proto"`
}

// PDMLProto represents a protocol layer in TShark's PDML output.
type PDMLProto struct {
	XMLName xml.Name   `xml:"proto"`
	Name    string     `xml:"name,attr"`
	Showname string     `xml:"showname,attr"`
	Fields   []PDMLField `xml:"field"`
}

// PDMLField represents a field in a protocol layer in TShark's PDML output.
type PDMLField struct {
	XMLName  xml.Name    `xml:"field"`
	Name     string      `xml:"name,attr"`
	Showname string      `xml:"showname,attr"`
	Value    string      `xml:"value,attr"`
	Show     string      `xml:"show,attr"`
	Pos      string      `xml:"pos,attr"`
	Size     string      `xml:"size,attr"`
	Fields   []PDMLField `xml:"field"`
}

// ParsePackets reads TShark PDML (XML) output from the provided reader and returns a slice of Packet objects.
func (p *XMLParser) ParsePackets(r io.Reader) ([]*packet.Packet, error) {
	// Create an XML decoder
	decoder := xml.NewDecoder(r)

	// Parse the PDML
	var pdml PDML
	if err := decoder.Decode(&pdml); err != nil {
		return nil, fmt.Errorf("failed to decode PDML: %w", err)
	}

	// Convert PDML packets to Packet objects
	packets := make([]*packet.Packet, 0, len(pdml.Packets))
	for _, pdmlPacket := range pdml.Packets {
		pkt, err := p.convertPDMLPacket(&pdmlPacket)
		if err != nil {
			return nil, fmt.Errorf("failed to convert PDML packet: %w", err)
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}

// convertPDMLPacket converts a PDMLPacket to a Packet.
func (p *XMLParser) convertPDMLPacket(pdmlPacket *PDMLPacket) (*packet.Packet, error) {
	// Create a new Packet
	pkt := &packet.Packet{}

	// Set frame number
	pkt.FrameNumber = pdmlPacket.FrameNum

	// Convert layers
	pkt.Layers = make([]packet.Layer, 0, len(pdmlPacket.Layers))
	for _, pdmlProto := range pdmlPacket.Layers {
		layer, err := p.convertPDMLProto(&pdmlProto)
		if err != nil {
			return nil, fmt.Errorf("failed to convert PDML proto: %w", err)
		}
		pkt.Layers = append(pkt.Layers, *layer)

		// Extract frame information from the frame layer
		if pdmlProto.Name == "frame" {
			p.extractFrameInfo(pkt, &pdmlProto)
		}
	}

	return pkt, nil
}

// convertPDMLProto converts a PDMLProto to a Layer.
func (p *XMLParser) convertPDMLProto(pdmlProto *PDMLProto) (*packet.Layer, error) {
	// Create a new Layer
	layer := &packet.Layer{
		Name:   pdmlProto.Name,
		Fields: make(map[string]interface{}),
	}

	// Convert fields
	for _, pdmlField := range pdmlProto.Fields {
		p.convertPDMLField(layer, &pdmlField)
	}

	return layer, nil
}

// convertPDMLField converts a PDMLField to a field in a Layer.
func (p *XMLParser) convertPDMLField(layer *packet.Layer, pdmlField *PDMLField) {
	// Use the show value if available, otherwise use the value
	value := pdmlField.Show
	if value == "" {
		value = pdmlField.Value
	}

	// Handle nested fields
	if len(pdmlField.Fields) > 0 {
		// Create a nested map for the field
		nestedFields := make(map[string]interface{})

		// Add the field's own value to the nested map
		if value != "" {
			nestedFields["_value"] = value
		}

		// Add nested fields
		for _, nestedField := range pdmlField.Fields {
			nestedLayer := &packet.Layer{
				Name:   pdmlField.Name,
				Fields: make(map[string]interface{}),
			}
			p.convertPDMLField(nestedLayer, &nestedField)

			// Add nested field to the nested map
			for k, v := range nestedLayer.Fields {
				nestedFields[k] = v
			}
		}

		// Add the nested map to the layer
		layer.Fields[pdmlField.Name] = nestedFields
	} else {
		// Add the field to the layer
		layer.Fields[pdmlField.Name] = value
	}

	// Add position and size if available and IncludeRaw is true
	if p.IncludeRaw && pdmlField.Pos != "" && pdmlField.Size != "" {
		pos, err := strconv.Atoi(pdmlField.Pos)
		if err == nil {
			layer.Fields[pdmlField.Name+"_pos"] = pos
		}

		size, err := strconv.Atoi(pdmlField.Size)
		if err == nil {
			layer.Fields[pdmlField.Name+"_size"] = size
		}
	}
}

// extractFrameInfo extracts frame information from a frame layer.
func (p *XMLParser) extractFrameInfo(pkt *packet.Packet, pdmlProto *PDMLProto) {
	for _, pdmlField := range pdmlProto.Fields {
		switch pdmlField.Name {
		case "frame.time_epoch":
			pkt.FrameTimeEpoch = pdmlField.Show
		case "frame.time":
			pkt.FrameTime = pdmlField.Show
		case "frame.len":
			pkt.FrameLen = pdmlField.Show
		case "frame.cap_len":
			pkt.FrameCapLen = pdmlField.Show
		}
	}
}

// ParseSinglePacket parses a single packet from an XML string.
func (p *XMLParser) ParseSinglePacket(xmlData string) (*packet.Packet, error) {
	// Wrap the XML data in a PDML root element if it doesn't have one
	xmlData = strings.TrimSpace(xmlData)
	if !strings.HasPrefix(xmlData, "<?xml") && !strings.HasPrefix(xmlData, "<pdml") {
		xmlData = "<pdml>" + xmlData + "</pdml>"
	}

	// Parse as PDML
	packets, err := p.ParsePackets(strings.NewReader(xmlData))
	if err != nil {
		return nil, err
	}

	// Return the first packet
	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets found in XML data")
	}

	return packets[0], nil
}

// ParseTSharkXML is a convenience function that creates an XMLParser and parses packets from a reader.
func ParseTSharkXML(r io.Reader, includeRaw bool) ([]*packet.Packet, error) {
	parser := NewXMLParser(WithXMLIncludeRaw(includeRaw))
	return parser.ParsePackets(r)
}

// ParseTSharkXMLString is a convenience function that creates an XMLParser and parses packets from a string.
func ParseTSharkXMLString(xmlData string, includeRaw bool) ([]*packet.Packet, error) {
	parser := NewXMLParser(WithXMLIncludeRaw(includeRaw))
	return parser.ParsePackets(strings.NewReader(xmlData))
}
