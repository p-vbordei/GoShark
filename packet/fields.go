package packet

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// LayerField holds all data about a field of a layer
type LayerField struct {
	Name          string
	Showname      string
	RawValue      string
	Show          string
	Hide          bool
	Pos           string
	Size          string
	Unmaskedvalue string
}

// NewLayerField creates a new layer field with the given attributes
func NewLayerField(name, showname, value, show, hide, pos, size, unmaskedvalue string) *LayerField {
	isHidden := false
	if hide == "yes" {
		isHidden = true
	}

	return &LayerField{
		Name:          name,
		Showname:      showname,
		RawValue:      value,
		Show:          show,
		Hide:          isHidden,
		Pos:           pos,
		Size:          size,
		Unmaskedvalue: unmaskedvalue,
	}
}

// GetDefaultValue returns the best 'value' string this field has
func (f *LayerField) GetDefaultValue() string {
	if f.Show != "" {
		return f.Show
	}
	if f.RawValue != "" {
		return f.RawValue
	}
	if f.Showname != "" {
		return f.Showname
	}
	return ""
}

// GetShownameValue returns the "pretty value" (as displayed by Wireshark) of the field
func (f *LayerField) GetShownameValue() string {
	if f.Showname != "" && strings.Contains(f.Showname, ": ") {
		parts := strings.SplitN(f.Showname, ": ", 2)
		return parts[1]
	}
	return ""
}

// GetShownameKey returns the "pretty name" (as displayed by Wireshark) of the field
func (f *LayerField) GetShownameKey() string {
	if f.Showname != "" && strings.Contains(f.Showname, ": ") {
		parts := strings.SplitN(f.Showname, ": ", 2)
		return parts[0]
	}
	return ""
}

// GetBinaryValue converts this field to binary (assuming it's a binary string)
func (f *LayerField) GetBinaryValue() ([]byte, error) {
	strRawValue := f.RawValue
	if len(strRawValue)%2 == 1 {
		strRawValue = "0" + strRawValue
	}

	return hex.DecodeString(strRawValue)
}

// GetIntValue returns the int value of this field (assuming it's represented as a decimal integer)
func (f *LayerField) GetIntValue() (int, error) {
	return strconv.Atoi(f.RawValue)
}

// GetHexValue returns the int value of this field if it's in base 16
func (f *LayerField) GetHexValue() (int64, error) {
	return strconv.ParseInt(strings.TrimPrefix(f.RawValue, "0x"), 16, 64)
}

// String returns a string representation of the field
func (f *LayerField) String() string {
	return f.GetDefaultValue()
}

// LayerFieldsContainer contains one or more fields of the same name
type LayerFieldsContainer struct {
	Fields []*LayerField
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

// String returns a string representation of the container
func (c *LayerFieldsContainer) String() string {
	mainField := c.GetMainField()
	if mainField != nil {
		return mainField.GetDefaultValue()
	}
	return ""
}

// GetDefaultValue returns the default value of the main field
func (c *LayerFieldsContainer) GetDefaultValue() string {
	mainField := c.GetMainField()
	if mainField != nil {
		return mainField.GetDefaultValue()
	}
	return ""
}

// GetBinaryValue returns the binary value of the main field
func (c *LayerFieldsContainer) GetBinaryValue() ([]byte, error) {
	mainField := c.GetMainField()
	if mainField != nil {
		return mainField.GetBinaryValue()
	}
	return nil, fmt.Errorf("no fields in container")
}

// GetIntValue returns the int value of the main field
func (c *LayerFieldsContainer) GetIntValue() (int, error) {
	mainField := c.GetMainField()
	if mainField != nil {
		return mainField.GetIntValue()
	}
	return 0, fmt.Errorf("no fields in container")
}

// GetHexValue returns the hex value of the main field
func (c *LayerFieldsContainer) GetHexValue() (int64, error) {
	mainField := c.GetMainField()
	if mainField != nil {
		return mainField.GetHexValue()
	}
	return 0, fmt.Errorf("no fields in container")
}
