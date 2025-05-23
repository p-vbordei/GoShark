package layers

import (
	"fmt"
	"io"
	"strings"
)

// SanitizeFieldName is a temporary placeholder for the actual function
// In a real module, this would be imported from the packet package
func SanitizeFieldName(fieldName string, prefix string) string {
	// Remove the prefix if it exists
	fieldName = strings.TrimPrefix(fieldName, prefix)
	// Replace dots and dashes with underscores
	return strings.ReplaceAll(strings.ReplaceAll(fieldName, ".", "_"), "-", "_")
}

// Colored is a temporary placeholder for the actual function
// In a real module, this would be imported from the packet package
func Colored(text string, color string, bold bool) string {
	return text
}

// JSONLayer represents a layer parsed from JSON output
type JSONLayer struct {
	*BaseLayer
	DuplicateLayers []*JSONLayer
	Fields          map[string]interface{}
	FullName        string
	IsIntermediate  bool
	Value           interface{}
	WrappedFields   map[string]interface{}
}

// NewJSONLayer creates a new JSONLayer from a layer name and JSON data
func NewJSONLayer(layerName string, layerData interface{}, fullName string, isIntermediate bool) *JSONLayer {
	baseLayer := NewBaseLayer(layerName)
	jsonLayer := &JSONLayer{
		BaseLayer:       baseLayer,
		DuplicateLayers: []*JSONLayer{},
		FullName:        fullName,
		IsIntermediate:  isIntermediate,
		WrappedFields:   make(map[string]interface{}),
	}

	// If no full name is provided, use the layer name
	if jsonLayer.FullName == "" {
		jsonLayer.FullName = jsonLayer.LayerName
	}

	// Handle different types of layer data
	switch data := layerData.(type) {
	case []interface{}:
		// Handle array of layers (duplicates)
		if len(data) > 0 {
			// First element is the main layer
			firstItem := data[0]
			// Rest are duplicates
			for _, item := range data[1:] {
				duplicate := NewJSONLayer(layerName, item, fullName, isIntermediate)
				jsonLayer.DuplicateLayers = append(jsonLayer.DuplicateLayers, duplicate)
			}
			// Process the first item
			switch firstItemData := firstItem.(type) {
			case map[string]interface{}:
				jsonLayer.Fields = firstItemData
			default:
				jsonLayer.Value = firstItemData
				jsonLayer.Fields = make(map[string]interface{})
			}
		} else {
			jsonLayer.Fields = make(map[string]interface{})
		}
	case map[string]interface{}:
		// Handle object layer
		jsonLayer.Fields = data
	default:
		// Handle primitive value
		jsonLayer.Value = data
		jsonLayer.Fields = make(map[string]interface{})
	}

	return jsonLayer
}

// GetField retrieves a field by its name
func (l *JSONLayer) GetField(name string) interface{} {
	// Check if we already have a wrapped field
	if field, ok := l.WrappedFields[name]; ok {
		return field
	}

	// Try to find the field
	field := l.getInternalFieldByName(name)
	if field == nil {
		// Check if it might be a "fake" field
		isFake := l.isFakeField(name)
		if !isFake {
			return nil
		}
	}

	// Create a wrapped field
	isFake := l.isFakeField(name)
	wrappedField := l.makeWrappedField(name, field, isFake)
	l.WrappedFields[name] = wrappedField
	return wrappedField
}

// FieldNames returns all field names in the layer
func (l *JSONLayer) FieldNames() []string {
	names := make([]string, 0)
	seenNames := make(map[string]bool)

	// Add fields that start with the full name
	for fieldName := range l.Fields {
		if strings.HasPrefix(fieldName, l.FullName) {
			sanitizedName := SanitizeFieldName(fieldName, l.FullName)
			if !seenNames[sanitizedName] {
				names = append(names, sanitizedName)
				seenNames[sanitizedName] = true
			}
		}
	}

	// Add fields that have a dot in them (nested fields)
	for name := range l.Fields {
		if strings.Contains(name, ".") {
			parts := strings.Split(name, ".")
			if len(parts) > 1 {
				sanitizedName := SanitizeFieldName(parts[len(parts)-1], "")
				if !seenNames[sanitizedName] {
					names = append(names, sanitizedName)
					seenNames[sanitizedName] = true
				}
			}
		}
	}

	return names
}

// HasField checks if a field exists in the layer
func (l *JSONLayer) HasField(name string) bool {
	// Check direct field names
	for _, fieldName := range l.FieldNames() {
		if strings.EqualFold(fieldName, name) {
			return true
		}
	}

	// Check dotted names (layer.sublayer.field)
	parts := strings.Split(name, ".")
	curLayer := l
	for _, part := range parts {
		field := curLayer.GetField(part)
		switch fieldValue := field.(type) {
		case *JSONLayer:
			curLayer = fieldValue
		default:
			if field == nil {
				return false
			}
			// If we found a field and it's not a layer, we're done
			return true
		}
	}

	return true
}

// prettyPrintLayerFields writes a formatted representation of the layer fields
func (l *JSONLayer) prettyPrintLayerFields(writer io.Writer) {
	for _, fieldLine := range l.getAllFieldLines() {
		if strings.Contains(fieldLine, ":") {
			parts := strings.SplitN(fieldLine, ":", 2)
			fieldName := parts[0]
			fieldValue := parts[1]
			fmt.Fprint(writer, Colored(fieldName+":", "green", true))
			fmt.Fprint(writer, fieldValue)
		} else {
			fmt.Fprint(writer, Colored(fieldLine, "", true))
		}
	}
}

// getAllFieldLines returns all lines that represent the fields of the layer
func (l *JSONLayer) getAllFieldLines() []string {
	lines := make([]string, 0)

	for _, field := range l.getAllFieldsWithAlternates() {
		lines = append(lines, l.getFieldOrLayerRepr(field)...)
	}

	return lines
}

// getFieldOrLayerRepr returns a string representation of a field or layer
func (l *JSONLayer) getFieldOrLayerRepr(field interface{}) []string {
	lines := make([]string, 0)

	switch fieldValue := field.(type) {
	case *JSONLayer:
		lines = append(lines, "\t"+fieldValue.LayerName+":\n")
		for _, line := range fieldValue.getAllFieldLines() {
			lines = append(lines, "\t"+line)
		}
	case []interface{}:
		for _, subfield := range fieldValue {
			lines = append(lines, l.getFieldOrLayerRepr(subfield)...)
		}
	default:
		lines = append(lines, fmt.Sprintf("\t%v\n", field))
	}

	return lines
}

// getAllFieldsWithAlternates returns all fields including alternatives
func (l *JSONLayer) getAllFieldsWithAlternates() []interface{} {
	fields := make([]interface{}, 0)

	// Add fields from the main layer
	for _, fieldValue := range l.Fields {
		fields = append(fields, fieldValue)
	}

	// Add fields from duplicate layers
	for _, duplicate := range l.DuplicateLayers {
		for _, field := range duplicate.getAllFieldsWithAlternates() {
			fields = append(fields, field)
		}
	}

	return fields
}

// getInternalFieldByName gets a field by its name
func (l *JSONLayer) getInternalFieldByName(name string) interface{} {
	// Try direct match
	if value, ok := l.Fields[name]; ok {
		return value
	}

	// Try with full name prefix
	fullNameField := l.FullName + "." + name
	if value, ok := l.Fields[fullNameField]; ok {
		return value
	}

	// Try case-insensitive match
	for fieldName, value := range l.Fields {
		if strings.EqualFold(sanitizeFieldName(fieldName, l.FullName), name) {
			return value
		}
	}

	return nil
}

// sanitizeFieldName sanitizes a field name for consistent comparison
func sanitizeFieldName(fieldName, layerName string) string {
	// Remove the layer name prefix if present
	prefix := layerName + "."
	if strings.HasPrefix(fieldName, prefix) {
		return fieldName[len(prefix):]
	}
	return fieldName
}

// makeWrappedField creates a wrapped field
func (l *JSONLayer) makeWrappedField(fieldName string, value interface{}, isFake bool) interface{} {
	if value == nil && isFake {
		// Create a fake field wrapper
		return NewJSONLayer("fake-field-wrapper", make(map[string]interface{}), fieldName, true)
	}

	// Check if the field is a map or array that should be converted to a sublayer
	switch fieldValue := value.(type) {
	case map[string]interface{}:
		return NewJSONLayer(fieldName, fieldValue, l.FullName+"."+fieldName, false)
	case []interface{}:
		return NewJSONLayer(fieldName, fieldValue, l.FullName+"."+fieldName, false)
	default:
		return value
	}
}

// isFakeField checks if a field might be a "fake" field
func (l *JSONLayer) isFakeField(name string) bool {
	// Check if any field starts with the potential fake field name
	potentialPrefix := l.FullName + "." + name + "."
	for fieldName := range l.Fields {
		if strings.HasPrefix(fieldName, potentialPrefix) {
			return true
		}
	}
	return false
}
