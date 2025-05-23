package packet

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Layer represents a generic protocol layer with dynamic fields.
type Layer struct {
	Name   string                 `json:"-"` // The name of the layer (e.g., "eth", "ip")
	Fields map[string]interface{} `json:",inline"` // All fields of the layer
}

// GetField retrieves a field's value from the layer by its name.
func (l *Layer) GetField(name string) interface{} {
	return l.Fields[name]
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

	// Unmarshal frame info and add frame layer first
	if frameRaw, ok := aux.Source.Layers["frame"]; ok {
		var frameLayer struct {
			FrameNumber    string `json:"frame.number"`
			FrameLen       string `json:"frame.len"`
			FrameCapLen    string `json:"frame.cap_len"`
			FrameTimeEpoch string `json:"frame.time_epoch"`
			FrameTime      string `json:"frame.time"`
			// Add other frame fields as needed
		}
		if err := json.Unmarshal(frameRaw, &frameLayer); err != nil {
			return fmt.Errorf("failed to unmarshal frame layer: %w", err)
		}
		p.FrameNumber = frameLayer.FrameNumber
		p.FrameLen = frameLayer.FrameLen
		p.FrameCapLen = frameLayer.FrameCapLen
		p.FrameTimeEpoch = frameLayer.FrameTimeEpoch
		p.FrameTime = frameLayer.FrameTime

		// Add frame layer to the ordered layers slice
		var frameFields map[string]interface{}
		json.Unmarshal(frameRaw, &frameFields) // Unmarshal to generic map for Layer.Fields
		p.Layers = append(p.Layers, Layer{Name: "frame", Fields: frameFields})
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
	transportLayers := []string{"tcp", "udp", "sctp", "dccp"} // Common transport layers
	for _, name := range transportLayers {
		if p.HasLayer(name) {
			return name
		}
	}
	return ""
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
