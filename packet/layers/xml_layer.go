package layers

import (
	"fmt"
	"io"
	"strings"
)

// LayerFieldsContainer is a temporary placeholder for the actual type
// In a real module, this would be imported from the packet package
type LayerFieldsContainer struct {
	Fields []*LayerField
}

// LayerField is a temporary placeholder for the actual type
// In a real module, this would be imported from the packet package
type LayerField struct {
	Name     string
	Showname string
	RawValue string
}

// NewLayerFieldsContainer creates a new container with the given main field
func NewLayerFieldsContainer(mainField *LayerField) *LayerFieldsContainer {
	return &LayerFieldsContainer{
		Fields: []*LayerField{mainField},
	}
}

// AddField adds a field to the container
func (c *LayerFieldsContainer) AddField(field *LayerField) {
	c.Fields = append(c.Fields, field)
}

// GetMainField returns the main (first) field in the container
func (c *LayerFieldsContainer) GetMainField() *LayerField {
	if len(c.Fields) > 0 {
		return c.Fields[0]
	}
	return nil
}

// GetAllFields returns all fields in the container
func (c *LayerFieldsContainer) GetAllFields() []*LayerField {
	return c.Fields
}

// GetDefaultValue returns the default value of the main field
func (c *LayerFieldsContainer) GetDefaultValue() string {
	mainField := c.GetMainField()
	if mainField != nil {
		return mainField.RawValue
	}
	return ""
}

// XMLLayer represents a layer parsed from XML output
type XMLLayer struct {
	*BaseLayer
	RawMode   bool
	AllFields map[string]*LayerFieldsContainer
}

// NewXMLLayer creates a new XMLLayer from XML data
func NewXMLLayer(name string, rawMode bool) *XMLLayer {
	baseLayer := NewBaseLayer(name)
	return &XMLLayer{
		BaseLayer: baseLayer,
		RawMode:   rawMode,
		AllFields: make(map[string]*LayerFieldsContainer),
	}
}

// AddField adds a field to the layer
func (l *XMLLayer) AddField(field *LayerField) {
	if field == nil {
		return
	}

	if container, ok := l.AllFields[field.Name]; ok {
		// Field name already exists, add this field to the container
		container.AddField(field)
	} else {
		// Create a new container for this field
		l.AllFields[field.Name] = NewLayerFieldsContainer(field)
	}
}

// GetField retrieves a field by its name
func (l *XMLLayer) GetField(name string) interface{} {
	// Try direct match first (faster)
	if field, ok := l.AllFields[name]; ok {
		if l.RawMode {
			return field.GetDefaultValue()
		}
		return field
	}

	// Try case-insensitive match with sanitized names
	sanitizedName := l.sanitizeFieldName(name)
	for fieldName, fieldValue := range l.AllFields {
		if l.sanitizeFieldName(fieldName) == sanitizedName {
			if l.RawMode {
				return fieldValue.GetDefaultValue()
			}
			return fieldValue
		}
	}

	return nil
}

// GetFieldValue tries getting the value of the given field
func (l *XMLLayer) GetFieldValue(name string, raw bool) interface{} {
	field := l.GetField(name)
	if field == nil {
		return nil
	}

	if raw {
		switch f := field.(type) {
		case *LayerFieldsContainer:
			mainField := f.GetMainField()
			if mainField != nil {
				return mainField.RawValue
			}
		case string:
			return f
		}
		return nil
	}

	return field
}

// FieldNames returns all field names in the layer
func (l *XMLLayer) FieldNames() []string {
	names := make([]string, 0, len(l.AllFields))
	for fieldName := range l.AllFields {
		names = append(names, l.sanitizeFieldName(fieldName))
	}
	return names
}

// GetLayerName returns the name of the layer
func (l *XMLLayer) GetLayerName() string {
	if l.LayerName == "fake-field-wrapper" {
		return DataLayerName
	}
	return l.LayerName
}

// prettyPrintLayerFields writes a formatted representation of the layer fields
func (l *XMLLayer) prettyPrintLayerFields(writer io.Writer) {
	for _, fieldLine := range l.getAllFieldLines() {
		if strings.Contains(fieldLine, ":") {
			parts := strings.SplitN(fieldLine, ":", 2)
			fieldName := parts[0]
			fieldValue := parts[1]
			// Use simple formatting instead of packet.Colored
			fmt.Fprintf(writer, "\033[32;1m%s:\033[0m%s", fieldName, fieldValue)
		} else {
			// Use simple formatting instead of packet.Colored
			fmt.Fprintf(writer, "\033[1m%s\033[0m", fieldLine)
		}
	}
}

// getAllFieldLines returns all lines that represent the fields of the layer
func (l *XMLLayer) getAllFieldLines() []string {
	lines := make([]string, 0)

	// Sort field names for consistent output
	fieldNames := l.FieldNames()

	for _, fieldName := range fieldNames {
		field := l.GetField(fieldName)
		if field != nil {
			switch f := field.(type) {
			case *LayerFieldsContainer:
				for _, subField := range f.GetAllFields() {
					lines = append(lines, fmt.Sprintf("\t%s: %s\n", subField.Name, subField.RawValue))
				}
			default:
				lines = append(lines, fmt.Sprintf("\t%s: %v\n", fieldName, field))
			}
		}
	}

	return lines
}

// sanitizeFieldName sanitizes an XML field name
func (l *XMLLayer) sanitizeFieldName(fieldName string) string {
	// Remove the prefix
	prefix := l.getFieldPrefix()
	fieldName = strings.TrimPrefix(fieldName, prefix)
	// Replace dots and dashes with underscores
	return strings.ReplaceAll(strings.ReplaceAll(fieldName, ".", "_"), "-", "_")
}

// getFieldPrefix returns the prefix for field names in the XML
func (l *XMLLayer) getFieldPrefix() string {
	if l.LayerName == "geninfo" {
		return ""
	}
	return l.LayerName + "."
}
