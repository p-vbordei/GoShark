package packet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FieldOffset represents the position and size of a field in the raw packet data.
type FieldOffset struct {
	Start  int    // Byte offset from the beginning of the packet
	Length int    // Length of the field in bytes
	Name   string // Field name
	Showname string // Field display name
}

// Field represents a protocol field with its value and metadata.
type Field struct {
	Name     string      // Field name
	Value    interface{} // Field value
	Showname string      // Field display name
	Offset   *FieldOffset // Field offset information, if available
}

// Layer represents a generic protocol layer with dynamic fields.
type Layer struct {
	Name   string                 `json:"-"` // The name of the layer (e.g., "eth", "ip")
	Fields map[string]interface{} `json:",inline"` // All fields of the layer
	Offsets map[string]*FieldOffset `json:"-"` // Field offsets for raw data access
	Pos    int                    `json:"-"` // Position of this layer in the packet (byte offset)
	Len    int                    `json:"-"` // Length of this layer in bytes
}

// GetField retrieves a field's value from the layer by its name.
func (l *Layer) GetField(name string) interface{} {
	return l.Fields[name]
}

// GetFieldHex retrieves a field's value as a hexadecimal string.
func (l *Layer) GetFieldHex(name string) string {
	val := l.GetField(name)
	if val == nil {
		return ""
	}
	
	// Convert to string if not already
	valStr := fmt.Sprintf("%v", val)
	
	// If it's already a hex string (starts with 0x), return it
	if strings.HasPrefix(valStr, "0x") {
		return valStr[2:] // Remove 0x prefix
	}
	
	// Try to convert to integer and then to hex
	if intVal, err := strconv.ParseInt(valStr, 10, 64); err == nil {
		return fmt.Sprintf("%x", intVal)
	}
	
	// Return as is if conversion fails
	return valStr
}

// GetFieldInt retrieves a field's value as an integer.
func (l *Layer) GetFieldInt(name string) (int64, error) {
	val := l.GetField(name)
	if val == nil {
		return 0, fmt.Errorf("field %s not found", name)
	}
	
	// Convert to string if not already
	valStr := fmt.Sprintf("%v", val)
	
	// If it's a hex string (starts with 0x), parse as hex
	if strings.HasPrefix(valStr, "0x") {
		return strconv.ParseInt(valStr[2:], 16, 64)
	}
	
	// Try to parse as decimal
	return strconv.ParseInt(valStr, 10, 64)
}

// GetFieldOffset retrieves the offset information for a field.
func (l *Layer) GetFieldOffset(name string) *FieldOffset {
	return l.Offsets[name]
}

// FieldNames returns a slice of all field names in the layer.
func (l *Layer) FieldNames() []string {
	names := make([]string, 0, len(l.Fields))
	for name := range l.Fields {
		names = append(names, name)
	}
	return names
}

// HasField checks if a field with the given name exists in the layer.
func (l *Layer) HasField(name string) bool {
	_, ok := l.Fields[name]
	return ok
}

// Get retrieves a field's value from the layer by its name, returning a defaultValue if not found.
func (l *Layer) Get(name string, defaultValue interface{}) interface{} {
	if val, ok := l.Fields[name]; ok {
		return val
	}
	return defaultValue
}

// PrettyPrint returns a formatted string representation of the layer.
func (l *Layer) PrettyPrint() string {
	s := fmt.Sprintf("Layer %s:\n", l.Name)
	for _, fieldName := range l.FieldNames() {
		s += fmt.Sprintf("  %s: %v\n", fieldName, l.Fields[fieldName])
	}
	return s
}

// Packet represents a decoded network packet from TShark.
type Packet struct {
	// _index field from TShark JSON
	Index struct {
		ProtocolID string `json:"protocol_id"`
		// Add other index fields if needed
	} `json:"_index"`

	// _source field from TShark JSON
	Source struct {
		Layers map[string]json.RawMessage `json:"layers"`
	} `json:"_source"`

	// Flattened metadata from frame layer for easier access, populated during UnmarshalJSON
	FrameNumber      string
	FrameLen         string
	FrameCapLen      string
	FrameTimeEpoch   string
	FrameTime        string

	// Raw packet data, populated during UnmarshalJSON if available
	RawData []byte

	// Ordered list of layers, populated during UnmarshalJSON
	Layers []Layer
}

// UnmarshalJSON custom unmarshaler for Packet to handle nested layers and frame info.
func (p *Packet) UnmarshalJSON(data []byte) error {
	// Use an auxiliary struct for initial unmarshaling to get _index and _source.layers
	aux := struct {
		Index  json.RawMessage `json:"_index"`
		Source struct {
			Layers map[string]json.RawMessage `json:"layers"`
		} `json:"_source"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Unmarshal _index
	if err := json.Unmarshal(aux.Index, &p.Index); err != nil {
		return fmt.Errorf("failed to unmarshal _index: %w", err)
	}

	// Process layers
	p.Layers = make([]Layer, 0, len(aux.Source.Layers))

	// Check if raw frame data is available
	if frameRawHex, ok := aux.Source.Layers["frame_raw"]; ok {
		var frameRawValue struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(frameRawHex, &frameRawValue); err == nil && frameRawValue.Value != "" {
			// Convert hex string to bytes
			frameRawValue.Value = strings.Replace(frameRawValue.Value, ":", "", -1)
			rawData, err := hex.DecodeString(frameRawValue.Value)
			if err == nil {
				p.RawData = rawData
			}
		}
	}

	// Unmarshal frame info and add frame layer first
	if frameRaw, ok := aux.Source.Layers["frame"]; ok {
		var frameLayer struct {
			FrameNumber    []struct{ Value string } `json:"frame.number"`
			FrameLen       []struct{ Value string } `json:"frame.len"`
			FrameCapLen    []struct{ Value string } `json:"frame.cap_len"`
			FrameTimeEpoch []struct{ Value string } `json:"frame.time_epoch"`
			FrameTime      []struct{ Value string } `json:"frame.time"`
			// Field position information
			FrameOffset    []struct{ 
				Pos string `json:"pos"` 
				Showname string `json:"showname"`
				Size string `json:"size"`
				Value string `json:"value"`
			} `json:"frame.offset"`
		}
		if err := json.Unmarshal(frameRaw, &frameLayer); err == nil {
			// Extract frame info for easier access
			if len(frameLayer.FrameNumber) > 0 {
				p.FrameNumber = frameLayer.FrameNumber[0].Value
			}
			if len(frameLayer.FrameLen) > 0 {
				p.FrameLen = frameLayer.FrameLen[0].Value
			}
			if len(frameLayer.FrameCapLen) > 0 {
				p.FrameCapLen = frameLayer.FrameCapLen[0].Value
			}
			if len(frameLayer.FrameTimeEpoch) > 0 {
				p.FrameTimeEpoch = frameLayer.FrameTimeEpoch[0].Value
			}
			if len(frameLayer.FrameTime) > 0 {
				p.FrameTime = frameLayer.FrameTime[0].Value
			}
			
			// Process field offsets if available
			if len(frameLayer.FrameOffset) > 0 {
				offsets := make(map[string]*FieldOffset)
				for _, offset := range frameLayer.FrameOffset {
					pos, _ := strconv.Atoi(offset.Pos)
					size, _ := strconv.Atoi(offset.Size)
					offsets["frame.offset"] = &FieldOffset{
						Start: pos,
						Length: size,
						Name: "frame.offset",
						Showname: offset.Showname,
					}
				}
				
				// Add offsets to the frame layer
				var frameFields map[string]interface{}
				json.Unmarshal(frameRaw, &frameFields) // Unmarshal to generic map for Layer.Fields
				p.Layers = append(p.Layers, Layer{
					Name: "frame", 
					Fields: frameFields,
					Offsets: offsets,
					Pos: 0, // Frame always starts at position 0
				})
				return nil
			}
		}
		
		// If we didn't already add the frame layer via offsets
		if len(p.Layers) == 0 {
			var frameFields map[string]interface{}
			json.Unmarshal(frameRaw, &frameFields) // Unmarshal to generic map for Layer.Fields
			p.Layers = append(p.Layers, Layer{Name: "frame", Fields: frameFields})
		}
	}

	// Collect other layer names for sorting
	var layerNames []string
	for name := range aux.Source.Layers {
		if name != "frame" { // Skip frame as it's already processed
			layerNames = append(layerNames, name)
		}
	}
	sort.Strings(layerNames) // Sort alphabetically for consistent order

	for _, layerName := range layerNames {
		rawLayer := aux.Source.Layers[layerName]
		layer := Layer{Name: layerName}
		if err := json.Unmarshal(rawLayer, &layer.Fields); err != nil {
			return fmt.Errorf("failed to unmarshal %s layer: %w", layerName, err)
		}
		p.Layers = append(p.Layers, layer)
	}

	return nil
}

// SniffTime returns the packet's capture time as a time.Time object.
func (p *Packet) SniffTime() (time.Time, error) {
	if p.FrameTimeEpoch == "" {
		return time.Time{}, fmt.Errorf("sniff time epoch not available")
	}
	epoch, err := strconv.ParseFloat(p.FrameTimeEpoch, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse sniff time epoch: %w", err)
	}
	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	return time.Unix(sec, nsec), nil
}

// GetLayer retrieves a layer by its name (case-insensitive).
func (p *Packet) GetLayer(name string) *Layer {
	for i := range p.Layers {
		// TShark layer names are typically lowercase
		if p.Layers[i].Name == name {
			return &p.Layers[i]
		}
	}
	return nil
}

// GetLayerByIndex retrieves a layer by its index.
func (p *Packet) GetLayerByIndex(index int) *Layer {
	if index >= 0 && index < len(p.Layers) {
		return &p.Layers[index]
	}
	return nil
}

// HasLayer checks if a layer with the given name exists in the packet.
func (p *Packet) HasLayer(name string) bool {
	return p.GetLayer(name) != nil
}

// GetMultipleLayers retrieves all layers of a specific type (case-insensitive).
func (p *Packet) GetMultipleLayers(name string) []Layer {
	var matchingLayers []Layer
	for _, layer := range p.Layers {
		if layer.Name == name {
			matchingLayers = append(matchingLayers, layer)
		}
	}
	return matchingLayers
}

// HighestLayer returns the name of the highest (last) layer in the packet.
func (p *Packet) HighestLayer() string {
	if len(p.Layers) == 0 {
		return ""
	}
	return p.Layers[len(p.Layers)-1].Name
}

// TransportLayer returns the name of the transport layer (tcp, udp, sctp, dccp) if present.
func (p *Packet) TransportLayer() string {
	transportLayers := []string{"tcp", "udp", "sctp", "dccp"}
	for _, layerName := range transportLayers {
		if p.HasLayer(layerName) {
			return layerName
		}
	}
	return ""
}

// GetRawPacket returns the raw packet data as bytes.
// Returns nil if raw data is not available.
func (p *Packet) GetRawPacket() []byte {
	// Check if we have raw data
	if p.RawData != nil && len(p.RawData) > 0 {
		return p.RawData
	}
	
	// If no raw data is available, check if we have a frame_raw field
	if frameLayer := p.GetLayer("frame"); frameLayer != nil {
		if frameRaw, ok := frameLayer.Fields["frame.raw"]; ok {
			// Try to convert to string and parse as hex
			rawStr := fmt.Sprintf("%v", frameRaw)
			// Remove colons if present
			rawStr = strings.Replace(rawStr, ":", "", -1)
			// Convert hex string to bytes
			rawData, err := hex.DecodeString(rawStr)
			if err == nil {
				return rawData
			}
		}
	}
	
	return nil
}

// GetLayerRawBytes returns the raw bytes for a specific layer.
// Returns nil if raw data or layer offset information is not available.
func (p *Packet) GetLayerRawBytes(layerName string) []byte {
	layer := p.GetLayer(layerName)
	if layer == nil || p.RawData == nil || layer.Pos < 0 || layer.Len <= 0 {
		return nil
	}
	
	// Make sure we don't go out of bounds
	if layer.Pos+layer.Len > len(p.RawData) {
		return nil
	}
	
	return p.RawData[layer.Pos:layer.Pos+layer.Len]
}

// GetFieldRawBytes returns the raw bytes for a specific field in a layer.
// Returns nil if raw data or field offset information is not available.
func (p *Packet) GetFieldRawBytes(layerName, fieldName string) []byte {
	layer := p.GetLayer(layerName)
	if layer == nil || p.RawData == nil {
		return nil
	}
	
	fieldOffset := layer.GetFieldOffset(fieldName)
	if fieldOffset == nil || fieldOffset.Start < 0 || fieldOffset.Length <= 0 {
		return nil
	}
	
	// Make sure we don't go out of bounds
	if fieldOffset.Start+fieldOffset.Length > len(p.RawData) {
		return nil
	}
	
	return p.RawData[fieldOffset.Start:fieldOffset.Start+fieldOffset.Length]
}

// NewPacketFromJSON takes raw TShark JSON output for a single packet and unmarshals it into a Packet struct.
// TShark JSON output is typically an array of packets, even for a single packet.
func NewPacketFromJSON(data []byte) (*Packet, error) {
	var rawPackets []json.RawMessage
	if err := json.Unmarshal(data, &rawPackets); err != nil {
		// If it's not an array, try unmarshalling directly as a single object (e.g., if only _source is provided)
		var p Packet
		if err := json.Unmarshal(data, &p); err == nil {
			return &p, nil
		}
		return nil, fmt.Errorf("failed to unmarshal raw packets JSON: %w", err)
	}

	if len(rawPackets) == 0 {
		return nil, fmt.Errorf("no packets found in JSON data")
	}

	p := &Packet{}
	if err := json.Unmarshal(rawPackets[0], p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal packet from raw message: %w", err)
	}
	return p, nil
}

// ParsePackets takes raw TShark JSON output (an array of packets) and unmarshals it into a slice of Packet structs.
func ParsePackets(data []byte) ([]*Packet, error) {
	var rawPackets []json.RawMessage
	if err := json.Unmarshal(data, &rawPackets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal raw packets JSON: %w", err)
	}

	var packets []*Packet
	for _, raw := range rawPackets {
		p := &Packet{}
		if err := json.Unmarshal(raw, p); err != nil {
			return nil, fmt.Errorf("failed to unmarshal packet: %w", err)
		}
		packets = append(packets, p)
	}
	return packets, nil
}
