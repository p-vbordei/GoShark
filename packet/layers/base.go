package layers

import (
	"fmt"
	"io"
	"strings"
)

// DataLayerName is the name of the data layer
const DataLayerName = "DATA"

// BaseLayer is the foundation for all protocol layers
type BaseLayer struct {
	LayerName string
}

// NewBaseLayer creates a new base layer with the given name
func NewBaseLayer(layerName string) *BaseLayer {
	return &BaseLayer{
		LayerName: layerName,
	}
}

// GetField retrieves a field by name (to be implemented by derived layers)
func (b *BaseLayer) GetField(name string) interface{} {
	panic("GetField must be implemented by derived layers")
}

// FieldNames returns the names of all fields in the layer (to be implemented by derived layers)
func (b *BaseLayer) FieldNames() []string {
	panic("FieldNames must be implemented by derived layers")
}

// HasField checks if a field exists in the layer
func (b *BaseLayer) HasField(name string) bool {
	for _, fieldName := range b.FieldNames() {
		if strings.EqualFold(fieldName, name) {
			return true
		}
	}
	return false
}

// Get retrieves a field value or returns a default if not found
func (b *BaseLayer) Get(name string, defaultValue interface{}) interface{} {
	if b.HasField(name) {
		return b.GetField(name)
	}
	return defaultValue
}

// GetLayerName returns the name of the layer
func (b *BaseLayer) GetLayerName() string {
	return b.LayerName
}

// PrettyPrint writes a formatted representation of the layer to the given writer
func (b *BaseLayer) PrettyPrint(writer io.Writer) {
	if b.LayerName == DataLayerName {
		fmt.Fprint(writer, "DATA")
		return
	}

	fmt.Fprintf(writer, "Layer %s:\n", strings.ToUpper(b.LayerName))
	b.prettyPrintLayerFields(writer)
}

// prettyPrintLayerFields writes a formatted representation of the layer fields (to be implemented by derived layers)
func (b *BaseLayer) prettyPrintLayerFields(writer io.Writer) {
	panic("prettyPrintLayerFields must be implemented by derived layers")
}

// String returns a string representation of the layer
func (b *BaseLayer) String() string {
	return fmt.Sprintf("<%s Layer>", strings.ToUpper(b.LayerName))
}
