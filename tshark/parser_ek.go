package tshark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/p-vbordei/GoShark/packet"
	"github.com/p-vbordei/GoShark/packet/layers"
)

// EKParser handles parsing of TShark Elastic Common Schema (-T ek) output.
//
// Real tshark -T ek output is newline-delimited JSON: alternating
// {"index":{...}} metadata lines and {"timestamp":"<epoch-ms>","layers":{...}}
// packet lines. EK field names are underscore-flattened and double-prefixed
// (e.g. the frame number is "frame_frame_number").
type EKParser struct {
	IncludeRaw bool
}

// NewEKParser creates a new EKParser instance.
func NewEKParser(options ...func(*EKParser)) *EKParser {
	parser := &EKParser{IncludeRaw: false}
	for _, option := range options {
		option(parser)
	}
	return parser
}

// WithEKIncludeRaw sets whether to include raw packet data in the parsed output.
func WithEKIncludeRaw(includeRaw bool) func(*EKParser) {
	return func(p *EKParser) { p.IncludeRaw = includeRaw }
}

// ekRecord is one newline-delimited JSON record of tshark -T ek output.
type ekRecord struct {
	Index     json.RawMessage `json:"index"`
	Timestamp string          `json:"timestamp"`
	Layers    json.RawMessage `json:"layers"`
}

// ekOrderedLayer is one entry from the EK "layers" object, in document order.
type ekOrderedLayer struct {
	name string
	raw  json.RawMessage
}

// decodeEKLayers walks the EK "layers" JSON object preserving key order.
func decodeEKLayers(raw json.RawMessage) ([]ekOrderedLayer, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("ek layers: expected JSON object")
	}

	var out []ekOrderedLayer
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)

		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		out = append(out, ekOrderedLayer{name: key, raw: val})
	}
	return out, nil
}

// ParsePackets reads TShark EK output (NDJSON) and returns the packets,
// skipping the {"index":...} metadata lines.
func (p *EKParser) ParsePackets(r io.Reader) ([]*packet.Packet, error) {
	decoder := json.NewDecoder(r)

	var packets []*packet.Packet
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("failed to decode EK record: %w", err)
		}
		pkt, ok, err := p.ParseRecord(raw)
		if err != nil {
			return nil, err
		}
		if ok {
			packets = append(packets, pkt)
		}
	}
	return packets, nil
}

// ParseRecord converts one EK NDJSON record into a Packet. The returned bool is
// false for non-packet records (the {"index":...} metadata lines), which
// callers should skip.
func (p *EKParser) ParseRecord(raw json.RawMessage) (*packet.Packet, bool, error) {
	var rec ekRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal EK record: %w", err)
	}
	if len(rec.Layers) == 0 {
		return nil, false, nil // an {"index":...} metadata line
	}

	ordered, err := decodeEKLayers(rec.Layers)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode EK layers: %w", err)
	}

	pkt := &packet.Packet{}
	// tshark -T ek emits the timestamp as epoch milliseconds.
	if ms, err := strconv.ParseInt(rec.Timestamp, 10, 64); err == nil {
		pkt.FrameTime = time.UnixMilli(ms).Format(time.RFC3339Nano)
	}

	pkt.Layers = make([]packet.Layer, 0, len(ordered))
	for _, ol := range ordered {
		layer, err := p.convertEKLayer(ol.name, ol.raw)
		if err != nil {
			return nil, false, fmt.Errorf("failed to convert layer %s: %w", ol.name, err)
		}
		if ol.name == "frame" {
			p.extractEKFrameInfo(pkt, layer.Fields)
		}
		pkt.Layers = append(pkt.Layers, *layer)
	}
	return pkt, true, nil
}

// extractEKFrameInfo fills the packet's frame metadata from an EK frame layer.
func (p *EKParser) extractEKFrameInfo(pkt *packet.Packet, fields map[string]interface{}) {
	pkt.FrameNumber = ekFieldString(fields, "frame_frame_number", "frame.number", "frame_number")
	pkt.FrameLen = ekFieldString(fields, "frame_frame_len", "frame.len", "frame_len")
	pkt.FrameCapLen = ekFieldString(fields, "frame_frame_cap_len", "frame.cap_len", "frame_cap_len")
	if epoch := ekFieldString(fields, "frame_frame_time_epoch", "frame.time_epoch", "frame_time_epoch"); epoch != "" {
		pkt.FrameTimeEpoch = epoch
	}
}

// ekFieldString returns the first present key's value, coerced to a string.
func ekFieldString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case string:
				return x
			case float64:
				return strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				return strconv.FormatBool(x)
			default:
				return fmt.Sprintf("%v", v)
			}
		}
	}
	return ""
}

// convertEKLayer converts a layer from EK format to a Layer.
func (p *EKParser) convertEKLayer(layerName string, layerData json.RawMessage) (*packet.Layer, error) {
	layer := &packet.Layer{
		Name:    layerName,
		Fields:  make(map[string]interface{}),
		Offsets: make(map[string]*packet.FieldOffset),
	}

	var fields map[string]interface{}
	if err := json.Unmarshal(layerData, &fields); err != nil {
		return nil, fmt.Errorf("failed to unmarshal layer data: %w", err)
	}

	for fieldName, fieldValue := range fields {
		layer.Fields[fieldName] = fieldValue
	}

	layer.EKLayer = layers.NewEKLayer(layerName, fields)
	return layer, nil
}

// ParseSinglePacket parses a single EK packet record from a JSON string.
func (p *EKParser) ParseSinglePacket(jsonData string) (*packet.Packet, error) {
	pkt, ok, err := p.ParseRecord(json.RawMessage(jsonData))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("EK record is not a packet line")
	}
	return pkt, nil
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
