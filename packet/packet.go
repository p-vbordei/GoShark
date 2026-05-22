package packet

import (
	"bytes"
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
	Name      string                 `json:"-"` // The name of the layer (e.g., "eth", "ip")
	Fields    map[string]interface{} `json:",inline"` // All fields of the layer
	Offsets   map[string]*FieldOffset `json:"-"` // Field offsets for raw data access
	Pos       int                    `json:"-"` // Position of this layer in the packet (byte offset)
	Len       int                    `json:"-"` // Length of this layer in bytes
	JSONLayer interface{}            `json:"-"` // Concrete layers.JSONLayer representation
	XMLLayer  interface{}            `json:"-"` // Concrete layers.XMLLayer representation
	EKLayer   interface{}            `json:"-"` // Concrete layers.EKLayer representation
}

// GetField retrieves a field's value from the layer by its name.
func (l *Layer) GetField(name string) interface{} {
	return l.Fields[name]
}

// Field looks up a field by short or fully-qualified name. A short name like
// "srcport" on a "tcp" layer resolves "tcp.srcport"; a name that already
// contains a "." is used verbatim. This mirrors pyshark's attribute access.
func (l *Layer) Field(name string) interface{} {
	if v, ok := l.Fields[name]; ok {
		return v
	}
	if !strings.Contains(name, ".") {
		if v, ok := l.Fields[l.Name+"."+name]; ok {
			return v
		}
	}
	return nil
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
	s := fmt.Sprintf("Layer %s:\n", strings.ToUpper(l.Name))
	names := l.FieldNames()
	sort.Strings(names)
	for _, fieldName := range names {
		s += fmt.Sprintf("\t%s: %v\n", fieldName, l.Fields[fieldName])
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

func parseInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	case string:
		if i, err := strconv.Atoi(val); err == nil {
			return i, true
		}
	}
	return 0, false
}

func extractHexFromFrameRaw(raw json.RawMessage) (string, error) {
	// Try array first
	var arr []interface{}
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		if hexStr, ok := arr[0].(string); ok {
			return hexStr, nil
		}
	}
	// Try object with "value"
	var obj struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Value != "" {
		return obj.Value, nil
	}
	return "", fmt.Errorf("failed to extract hex from frame_raw")
}

func extractOffsets(fields map[string]interface{}, offsets map[string]*FieldOffset) {
	for k, v := range fields {
		if strings.HasSuffix(k, "_raw") {
			fieldName := strings.TrimSuffix(k, "_raw")
			if slice, ok := v.([]interface{}); ok && len(slice) >= 3 {
				start, ok1 := parseInt(slice[1])
				length, ok2 := parseInt(slice[2])
				if ok1 && ok2 {
					offsets[fieldName] = &FieldOffset{
						Start:  start,
						Length: length,
						Name:   fieldName,
					}
				}
			}
		} else if nextMap, ok := v.(map[string]interface{}); ok {
			extractOffsets(nextMap, offsets)
		} else if sliceOfInterfaces, ok := v.([]interface{}); ok {
			for _, item := range sliceOfInterfaces {
				if nextMap, ok := item.(map[string]interface{}); ok {
					extractOffsets(nextMap, offsets)
				}
			}
		}
	}
}

// orderedLayer is one entry from the _source.layers object, in document order.
type orderedLayer struct {
	name string
	raw  json.RawMessage
}

// decodeOrderedLayers walks a JSON object preserving key order. When a key's
// value is an array (tshark merges duplicate layer keys under --no-duplicate-keys),
// each element becomes its own entry so GetMultipleLayers keeps working.
func decodeOrderedLayers(raw json.RawMessage) ([]orderedLayer, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("layers: expected JSON object")
	}

	var out []orderedLayer
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

		// Duplicate layer keys are merged by --no-duplicate-keys into an array
		// of layer objects, which must be split back into separate layers.
		// A "_raw" key instead carries a [hex, pos, size, ...] position array
		// that must NOT be split — keep those as a single entry.
		trimmed := bytes.TrimSpace(val)
		if len(trimmed) > 0 && trimmed[0] == '[' && !strings.HasSuffix(key, "_raw") {
			var arr []json.RawMessage
			if err := json.Unmarshal(trimmed, &arr); err == nil && len(arr) > 0 {
				allObjects := true
				for _, el := range arr {
					if e := bytes.TrimSpace(el); len(e) == 0 || e[0] != '{' {
						allObjects = false
						break
					}
				}
				if allObjects {
					for _, el := range arr {
						out = append(out, orderedLayer{name: key, raw: el})
					}
					continue
				}
			}
		}
		out = append(out, orderedLayer{name: key, raw: val})
	}
	return out, nil
}

// coerceFieldString turns a tshark JSON field value into its string form.
// Real tshark -T json emits plain strings; it also accepts a one-element array
// or an object with a value/show key for robustness across output modes.
func coerceFieldString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case []interface{}:
		if len(x) > 0 {
			return coerceFieldString(x[0])
		}
	case map[string]interface{}:
		for _, k := range []string{"value", "show"} {
			if s, ok := x[k]; ok {
				return coerceFieldString(s)
			}
		}
	}
	return ""
}

// UnmarshalJSON custom unmarshaler for Packet. It parses real tshark -T json
// output, preserving the document order of protocol layers.
func (p *Packet) UnmarshalJSON(data []byte) error {
	aux := struct {
		Index  json.RawMessage `json:"_index"`
		Source struct {
			Layers json.RawMessage `json:"layers"`
		} `json:"_source"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// _index is usually a string, occasionally an object.
	var indexStr string
	if err := json.Unmarshal(aux.Index, &indexStr); err == nil {
		p.Index.ProtocolID = indexStr
	} else {
		_ = json.Unmarshal(aux.Index, &p.Index)
	}

	ordered, err := decodeOrderedLayers(aux.Source.Layers)
	if err != nil {
		return fmt.Errorf("failed to decode layers: %w", err)
	}

	// Index raw siblings (frame_raw, ip_raw, ...) by base name for offsets.
	rawByBase := map[string]json.RawMessage{}
	for _, ol := range ordered {
		if strings.HasSuffix(ol.name, "_raw") {
			rawByBase[strings.TrimSuffix(ol.name, "_raw")] = ol.raw
		}
	}
	if fr, ok := rawByBase["frame"]; ok {
		if hexStr, err := extractHexFromFrameRaw(fr); err == nil {
			hexStr = strings.ReplaceAll(hexStr, ":", "")
			if rawData, err := hex.DecodeString(hexStr); err == nil {
				p.RawData = rawData
			}
		}
	}

	p.Layers = make([]Layer, 0, len(ordered))
	for _, ol := range ordered {
		if strings.HasSuffix(ol.name, "_raw") {
			continue
		}

		layer := Layer{Name: ol.name, Offsets: make(map[string]*FieldOffset)}
		if err := json.Unmarshal(ol.raw, &layer.Fields); err != nil {
			return fmt.Errorf("failed to unmarshal %s layer: %w", ol.name, err)
		}

		// Layer byte position/length from the matching _raw sibling.
		if rawBytes, ok := rawByBase[ol.name]; ok {
			var rawArr []interface{}
			if err := json.Unmarshal(rawBytes, &rawArr); err == nil && len(rawArr) >= 3 {
				if pos, ok1 := parseInt(rawArr[1]); ok1 {
					layer.Pos = pos
				}
				if length, ok2 := parseInt(rawArr[2]); ok2 {
					layer.Len = length
				}
			}
		}

		extractOffsets(layer.Fields, layer.Offsets)

		if ol.name == "frame" {
			p.FrameNumber = coerceFieldString(layer.Fields["frame.number"])
			p.FrameLen = coerceFieldString(layer.Fields["frame.len"])
			p.FrameCapLen = coerceFieldString(layer.Fields["frame.cap_len"])
			p.FrameTimeEpoch = coerceFieldString(layer.Fields["frame.time_epoch"])
			p.FrameTime = coerceFieldString(layer.Fields["frame.time"])
		}

		p.Layers = append(p.Layers, layer)
	}

	return nil
}

// SniffTimestamp returns the raw capture timestamp string (frame.time_epoch).
func (p *Packet) SniffTimestamp() string {
	return p.FrameTimeEpoch
}

// SniffTime returns the packet's capture time as a time.Time object. It accepts
// either a float epoch (frame.time_epoch's usual form) or an ISO-8601 timestamp
// (tshark renders absolute-time fields per the Wireshark time-format preference),
// falling back to frame.time.
func (p *Packet) SniffTime() (time.Time, error) {
	s := p.FrameTimeEpoch
	if s == "" {
		s = p.FrameTime
	}
	if s == "" {
		return time.Time{}, fmt.Errorf("sniff time not available")
	}

	if epoch, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(epoch)
		nsec := int64((epoch - float64(sec)) * 1e9)
		return time.Unix(sec, nsec), nil
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse sniff time %q", s)
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

// Layer retrieves a layer by name (alias of GetLayer, pyshark-style accessor).
func (p *Packet) Layer(name string) *Layer {
	return p.GetLayer(name)
}

// InterfaceCaptured returns the capture interface name/id/description from the
// frame layer, or "" when unavailable.
func (p *Packet) InterfaceCaptured() string {
	f := p.GetLayer("frame")
	if f == nil {
		return ""
	}
	for _, k := range []string{"frame.interface_name", "frame.interface_id", "frame.interface_description"} {
		if v, ok := f.Fields[k]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// String renders the packet layer-by-layer (pyshark's pretty_print equivalent).
func (p *Packet) String() string {
	var b strings.Builder
	if p.FrameNumber != "" {
		fmt.Fprintf(&b, "Packet (frame %s)\n", p.FrameNumber)
	} else {
		b.WriteString("Packet\n")
	}
	for i := range p.Layers {
		b.WriteString(p.Layers[i].PrettyPrint())
	}
	return b.String()
}

// PrettyPrint is an alias for String.
func (p *Packet) PrettyPrint() string {
	return p.String()
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
