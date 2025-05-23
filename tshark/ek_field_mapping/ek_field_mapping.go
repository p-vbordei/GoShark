package ek_field_mapping

import (
	"strconv"
	"strings"
	"time"
)

// FieldMapping defines how to cast a field value
type FieldMapping struct {
	LayerName  string
	FieldName  string
	TargetType string
}

// FieldMappings is a collection of field mappings
type FieldMappings struct {
	mappings []FieldMapping
}

// Default mappings for common fields
var defaultMappings = []FieldMapping{
	{"frame", "frame_time_epoch", "timestamp"},
	{"frame", "frame_time_relative", "float"},
	{"frame", "frame_len", "int"},
	{"frame", "frame_cap_len", "int"},
	{"frame", "frame_marked", "bool"},
	{"frame", "frame_ignored", "bool"},
	
	{"ip", "ip_version", "int"},
	{"ip", "ip_hdr_len", "int"},
	{"ip", "ip_dsfield_dscp", "int"},
	{"ip", "ip_len", "int"},
	{"ip", "ip_id", "int"},
	{"ip", "ip_flags", "int"},
	{"ip", "ip_ttl", "int"},
	{"ip", "ip_proto", "int"},
	{"ip", "ip_checksum", "int"},
	
	{"tcp", "tcp_srcport", "int"},
	{"tcp", "tcp_dstport", "int"},
	{"tcp", "tcp_seq", "int"},
	{"tcp", "tcp_ack", "int"},
	{"tcp", "tcp_hdr_len", "int"},
	{"tcp", "tcp_flags", "int"},
	{"tcp", "tcp_window_size", "int"},
	{"tcp", "tcp_checksum", "int"},
	{"tcp", "tcp_urgent_pointer", "int"},
	
	{"udp", "udp_srcport", "int"},
	{"udp", "udp_dstport", "int"},
	{"udp", "udp_length", "int"},
	{"udp", "udp_checksum", "int"},
	
	{"dns", "dns_id", "int"},
	{"dns", "dns_flags", "int"},
	{"dns", "dns_count_queries", "int"},
	{"dns", "dns_count_answers", "int"},
	{"dns", "dns_count_auth_rr", "int"},
	{"dns", "dns_count_add_rr", "int"},
	
	{"http", "http_response_code", "int"},
	{"http", "http_content_length", "int"},
}

// NewFieldMappings creates a new field mappings instance
func NewFieldMappings() *FieldMappings {
	return &FieldMappings{
		mappings: defaultMappings,
	}
}

// AddMapping adds a new field mapping
func (m *FieldMappings) AddMapping(layerName, fieldName, targetType string) {
	m.mappings = append(m.mappings, FieldMapping{
		LayerName:  layerName,
		FieldName:  fieldName,
		TargetType: targetType,
	})
}

// GetMapping gets the mapping for a field
func (m *FieldMappings) GetMapping(layerName, fieldName string) (string, bool) {
	// Normalize names
	layerName = strings.ToLower(layerName)
	fieldName = strings.ToLower(fieldName)

	// Check for exact match
	for _, mapping := range m.mappings {
		if mapping.LayerName == layerName && mapping.FieldName == fieldName {
			return mapping.TargetType, true
		}
	}

	// Check for partial match (just the field name)
	for _, mapping := range m.mappings {
		if mapping.FieldName == fieldName {
			return mapping.TargetType, true
		}
	}

	return "", false
}

// CastFieldValue casts a field value to the appropriate type
func CastFieldValue(layerName, fieldName string, value interface{}) interface{} {
	// Get the mapping
	mappings := NewFieldMappings()
	targetType, found := mappings.GetMapping(layerName, fieldName)
	if !found {
		// No mapping found, return as is
		return value
	}

	// Cast the value based on the target type
	switch targetType {
	case "int":
		return castToInt(value)
	case "float":
		return castToFloat(value)
	case "bool":
		return castToBool(value)
	case "timestamp":
		return castToTimestamp(value)
	default:
		return value
	}
}

// castToInt casts a value to an integer
func castToInt(value interface{}) interface{} {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		// Try to parse as decimal
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		// Try to parse as hex
		if strings.HasPrefix(v, "0x") {
			if i, err := strconv.ParseInt(v[2:], 16, 64); err == nil {
				return int(i)
			}
		}
	}
	return value
}

// castToFloat casts a value to a float
func castToFloat(value interface{}) interface{} {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return value
}

// castToBool casts a value to a boolean
func castToBool(value interface{}) interface{} {
	switch v := value.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int64:
		return v != 0
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
		// Handle "1" and "0" strings
		if v == "1" {
			return true
		}
		if v == "0" {
			return false
		}
	}
	return value
}

// castToTimestamp casts a value to a timestamp
func castToTimestamp(value interface{}) interface{} {
	switch v := value.(type) {
	case time.Time:
		return v
	case float64:
		// Assume Unix timestamp in seconds
		return time.Unix(int64(v), int64((v-float64(int64(v)))*1e9))
	case string:
		// Try to parse as float first (Unix timestamp)
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return time.Unix(int64(f), int64((f-float64(int64(f)))*1e9))
		}
		// Try to parse as RFC3339
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
		// Try to parse as RFC3339Nano
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
	}
	return value
}
