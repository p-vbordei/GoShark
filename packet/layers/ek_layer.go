package layers

import (
	"fmt"
	"io"
	"strings"
)

// Temporary import fix - in a real module these would be proper imports
// These are placeholders for the actual imports that would be used in a Go module
type fieldMapping interface {
	CastFieldValue(layerName, fieldName string, value interface{}) interface{}
}

// EKLayer represents a layer parsed from Elastic Common Schema output
type EKLayer struct {
	*BaseLayer
	FieldsDict map[string]interface{}
}

// NewEKLayer creates a new EKLayer from a layer name and field dictionary
func NewEKLayer(layerName string, fieldsDict map[string]interface{}) *EKLayer {
	baseLayer := NewBaseLayer(layerName)
	eklayer := &EKLayer{
		BaseLayer:  baseLayer,
		FieldsDict: fieldsDict,
	}
	// Initialize any other fields if needed
	return eklayer
}

// GetField retrieves a field by its name
func (l *EKLayer) GetField(name string) interface{} {
	// Replace dots with underscores for EK field names
	name = strings.ReplaceAll(name, ".", "_")

	// Check if the field exists directly
	if _, ok := l.FieldsDict[name]; ok {
		return l.getFieldValue(name)
	}

	// Check for nested fields with prefixes
	for _, prefix := range l.getPossibleLayerPrefixes() {
		nestedField := l.getNestedField(prefix, name)
		if nestedField != nil {
			return nestedField
		}
	}

	return nil
}

// HasField checks if a field exists in the layer
func (l *EKLayer) HasField(name string) bool {
	return l.GetField(name) != nil
}

// FieldNames returns all field names in the layer
func (l *EKLayer) FieldNames() []string {
	// Get unique field name prefixes (first part before underscore)
	prefixSet := make(map[string]bool)
	for fieldName := range l.AllFieldNames() {
		parts := strings.SplitN(fieldName, "_", 2)
		if len(parts) > 0 {
			prefixSet[parts[0]] = true
		}
	}

	// Convert to slice
	names := make([]string, 0, len(prefixSet))
	for prefix := range prefixSet {
		names = append(names, prefix)
	}

	return names
}

// AllFieldNames returns all field names including subfields
func (l *EKLayer) AllFieldNames() map[string]bool {
	names := make(map[string]bool)

	for fieldName := range l.FieldsDict {
		for _, prefix := range l.getPossibleLayerPrefixes() {
			if strings.HasPrefix(fieldName, prefix) {
				names[removeEKPrefix(prefix, fieldName)] = true
				break
			}
		}
	}

	return names
}

// GetFieldAsList returns a field as a list even if it's a single value
func (l *EKLayer) GetFieldAsList(name string) []interface{} {
	fieldValue := l.GetField(name)
	if fieldValue == nil {
		return nil
	}

	// If it's already a slice, return it
	if slice, ok := fieldValue.([]interface{}); ok {
		return slice
	}

	// Otherwise, wrap it in a slice
	return []interface{}{fieldValue}
}

// prettyPrintLayerFields writes a formatted representation of the layer fields
func (l *EKLayer) prettyPrintLayerFields(writer io.Writer) {
	// Sort field names for consistent output
	fieldNames := l.FieldNames()

	for _, fieldName := range fieldNames {
		field := l.GetField(fieldName)
		if field != nil {
			fmt.Fprintf(writer, "\t%s: %v\n", fieldName, field)
		}
	}
}

// getFieldValue gets the field value, optionally casting it using the field mapping
func (l *EKLayer) getFieldValue(fullFieldName string) interface{} {
	fieldValue := l.FieldsDict[fullFieldName]
	// In a real implementation, this would use the proper import
	// return ek_field_mapping.CastFieldValue(l.LayerName, fullFieldName, fieldValue)
	// For now, just return the value as is
	return fieldValue
}

// getNestedField gets a field that is directly on the layer
func (l *EKLayer) getNestedField(prefix, name string) interface{} {
	// Try direct match with prefix
	fieldEKName := fmt.Sprintf("%s_%s", prefix, name)
	if _, ok := l.FieldsDict[fieldEKName]; ok {
		if l.fieldHasSubfields(fieldEKName) {
			return NewEKMultiField(l, name, l.getFieldValue(fieldEKName))
		}
		return l.getFieldValue(fieldEKName)
	}

	// Check for nested fields
	for possibleNestedName := range l.FieldsDict {
		if strings.HasPrefix(possibleNestedName, fieldEKName+"_") {
			return NewEKMultiField(l, name, nil)
		}
	}

	return nil
}

// fieldHasSubfields checks if a field has subfields
func (l *EKLayer) fieldHasSubfields(fieldEKName string) bool {
	for name := range l.FieldsDict {
		if strings.HasPrefix(name, fieldEKName+"_") {
			return true
		}
	}
	return false
}

// getPossibleLayerPrefixes returns possible prefixes for this layer
func (l *EKLayer) getPossibleLayerPrefixes() []string {
	// For EK format, layer names can have multiple possible prefixes
	// For example, "ip" layer might have fields with prefixes "ip", "ip_src", "ip_dst", etc.
	prefixes := []string{l.LayerName}

	// Add common prefixes for certain layers
	switch l.LayerName {
	case "ip":
		prefixes = append(prefixes, "ip_src", "ip_dst")
	case "tcp":
		prefixes = append(prefixes, "tcp_srcport", "tcp_dstport")
	case "udp":
		prefixes = append(prefixes, "udp_srcport", "udp_dstport")
	case "http":
		prefixes = append(prefixes, "http_request", "http_response")
	case "dns":
		prefixes = append(prefixes, "dns_query", "dns_response")
	}

	return prefixes
}

// EKMultiField represents a field with subfields in EK format
type EKMultiField struct {
	ContainingLayer *EKLayer
	FullName        string
	Value           interface{}
}

// NewEKMultiField creates a new EKMultiField
func NewEKMultiField(containingLayer *EKLayer, fullName string, value interface{}) *EKMultiField {
	return &EKMultiField{
		ContainingLayer: containingLayer,
		FullName:        fullName,
		Value:           value,
	}
}

// GetField retrieves a subfield by name
func (f *EKMultiField) GetField(fieldName string) interface{} {
	// Construct the full field name
	fullFieldName := fmt.Sprintf("%s_%s", f.FullName, fieldName)
	return f.ContainingLayer.GetField(fullFieldName)
}

// Subfields returns all subfield names
func (f *EKMultiField) Subfields() []string {
	subfields := make([]string, 0)
	prefix := f.FullName + "_"

	for fieldName := range f.ContainingLayer.AllFieldNames() {
		if strings.HasPrefix(fieldName, prefix) {
			subfieldName := strings.TrimPrefix(fieldName, prefix)
			if !strings.Contains(subfieldName, "_") {
				subfields = append(subfields, subfieldName)
			}
		}
	}

	return subfields
}

// String returns a string representation of the field
func (f *EKMultiField) String() string {
	if f.Value != nil {
		return fmt.Sprintf("%v", f.Value)
	}
	return fmt.Sprintf("<EKMultiField %s>", f.FullName)
}

// removeEKPrefix removes the prefix and underscore from a field name
func removeEKPrefix(prefix, value string) string {
	return strings.TrimPrefix(value, prefix+"_")
}
