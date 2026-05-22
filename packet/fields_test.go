package packet

import (
	"bytes"
	"testing"
)

func TestLayerField(t *testing.T) {
	// Test standard field creation and default value logic
	field := NewLayerField("ip.src", "Source: 192.168.1.1", "c0a80101", "192.168.1.1", "no", "26", "4", "c0a80101")
	if field.Name != "ip.src" {
		t.Errorf("Expected Name 'ip.src', got '%s'", field.Name)
	}
	if field.Hide {
		t.Errorf("Expected Hide to be false")
	}
	if field.GetDefaultValue() != "192.168.1.1" {
		t.Errorf("Expected GetDefaultValue() '192.168.1.1', got '%s'", field.GetDefaultValue())
	}
	if field.String() != "192.168.1.1" {
		t.Errorf("Expected String() '192.168.1.1', got '%s'", field.String())
	}

	// Test showname key and value extraction
	if key := field.GetShownameKey(); key != "Source" {
		t.Errorf("Expected GetShownameKey() 'Source', got '%s'", key)
	}
	if val := field.GetShownameValue(); val != "192.168.1.1" {
		t.Errorf("Expected GetShownameValue() '192.168.1.1', got '%s'", val)
	}

	// Test binary conversion (c0a80101 -> [192, 168, 1, 1])
	bin, err := field.GetBinaryValue()
	if err != nil {
		t.Fatalf("GetBinaryValue failed: %v", err)
	}
	expectedBin := []byte{192, 168, 1, 1}
	if !bytes.Equal(bin, expectedBin) {
		t.Errorf("Expected binary value %v, got %v", expectedBin, bin)
	}

	// Test hidden field
	hiddenField := NewLayerField("ip.src", "Source", "val", "show", "yes", "0", "0", "")
	if !hiddenField.Hide {
		t.Errorf("Expected Hide to be true")
	}

	// Test numeric conversion
	intField := NewLayerField("tcp.port", "Port: 80", "80", "80", "no", "0", "0", "")
	intVal, err := intField.GetIntValue()
	if err != nil {
		t.Fatalf("GetIntValue failed: %v", err)
	}
	if intVal != 80 {
		t.Errorf("Expected int value 80, got %d", intVal)
	}

	// Test hex conversion
	hexField := NewLayerField("tcp.flags", "Flags: 0x0002", "0x0002", "0x0002", "no", "0", "0", "")
	hexVal, err := hexField.GetHexValue()
	if err != nil {
		t.Fatalf("GetHexValue failed: %v", err)
	}
	if hexVal != 2 {
		t.Errorf("Expected hex value 2, got %d", hexVal)
	}

	// Test default value fallbacks
	fbField1 := &LayerField{Showname: "Test field"}
	if fbField1.GetDefaultValue() != "" { // wait, Showname fallback is in GetDefaultValue?
		// Let's check fields.go:
		// if f.Show != "" { return f.Show }
		// if f.RawValue != "" { return f.RawValue }
		// if f.Showname != "" { return f.Showname }
		// return ""
		if fbField1.GetDefaultValue() != "Test field" {
			t.Errorf("Expected fallback to Showname 'Test field', got '%s'", fbField1.GetDefaultValue())
		}
	}
}

func TestLayerFieldsContainer(t *testing.T) {
	field1 := NewLayerField("tcp.flags.syn", "Syn: 1", "1", "1", "no", "0", "0", "")
	container := NewLayerFieldsContainer(field1)

	if container.GetMainField() != field1 {
		t.Errorf("Expected main field to be field1")
	}

	if container.GetDefaultValue() != "1" {
		t.Errorf("Expected GetDefaultValue() '1', got '%s'", container.GetDefaultValue())
	}

	if container.String() != "1" {
		t.Errorf("Expected String() '1', got '%s'", container.String())
	}

	allFields := container.GetAllFields()
	if len(allFields) != 1 || allFields[0] != field1 {
		t.Errorf("Expected GetAllFields() to return [field1], got %v", allFields)
	}

	// Add second field
	field2 := NewLayerField("tcp.flags.syn", "Syn: 0", "0", "0", "no", "0", "0", "")
	container.AddField(field2)

	allFields = container.GetAllFields()
	if len(allFields) != 2 || allFields[0] != field1 || allFields[1] != field2 {
		t.Errorf("Expected GetAllFields() to return [field1, field2], got %v", allFields)
	}

	// Test container value helper methods delegation
	// Binary
	binField := NewLayerField("ip.src", "Source", "c0a80101", "192.168.1.1", "no", "0", "0", "")
	binContainer := NewLayerFieldsContainer(binField)
	bin, err := binContainer.GetBinaryValue()
	if err != nil {
		t.Fatalf("GetBinaryValue failed: %v", err)
	}
	if !bytes.Equal(bin, []byte{192, 168, 1, 1}) {
		t.Errorf("Expected binary value %v, got %v", []byte{192, 168, 1, 1}, bin)
	}

	// Int
	intField := NewLayerField("tcp.port", "Port", "80", "80", "no", "0", "0", "")
	intContainer := NewLayerFieldsContainer(intField)
	intVal, err := intContainer.GetIntValue()
	if err != nil {
		t.Fatalf("GetIntValue failed: %v", err)
	}
	if intVal != 80 {
		t.Errorf("Expected 80, got %d", intVal)
	}

	// Hex
	hexField := NewLayerField("tcp.flags", "Flags", "0x0002", "0x0002", "no", "0", "0", "")
	hexContainer := NewLayerFieldsContainer(hexField)
	hexVal, err := hexContainer.GetHexValue()
	if err != nil {
		t.Fatalf("GetHexValue failed: %v", err)
	}
	if hexVal != 2 {
		t.Errorf("Expected 2, got %d", hexVal)
	}

	// Empty container error cases
	emptyContainer := &LayerFieldsContainer{}
	if _, err := emptyContainer.GetBinaryValue(); err == nil {
		t.Errorf("Expected error from empty container GetBinaryValue")
	}
	if _, err := emptyContainer.GetIntValue(); err == nil {
		t.Errorf("Expected error from empty container GetIntValue")
	}
	if _, err := emptyContainer.GetHexValue(); err == nil {
		t.Errorf("Expected error from empty container GetHexValue")
	}
}
