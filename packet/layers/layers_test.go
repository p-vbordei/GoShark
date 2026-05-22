package layers

import (
	"bytes"
	"strings"
	"testing"

	"GoShark/packet"
)

func TestXMLLayer(t *testing.T) {
	// Test creating XMLLayer with rawMode = false
	xmlLayer := NewXMLLayer("ip", false)
	if xmlLayer.GetLayerName() != "ip" {
		t.Errorf("Expected layer name 'ip', got '%s'", xmlLayer.GetLayerName())
	}

	field1 := packet.NewLayerField("ip.src", "Source: 192.168.1.1", "c0a80101", "192.168.1.1", "no", "0", "0", "")
	xmlLayer.AddField(field1)

	// Test GetField
	f := xmlLayer.GetField("src")
	if f == nil {
		t.Fatalf("Expected to get field 'src'")
	}
	container, ok := f.(*packet.LayerFieldsContainer)
	if !ok {
		t.Fatalf("Expected field 'src' to be *LayerFieldsContainer, got %T", f)
	}
	if container.GetDefaultValue() != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%s'", container.GetDefaultValue())
	}

	// Test GetFieldValue
	valRaw := xmlLayer.GetFieldValue("src", true)
	if valRaw != "c0a80101" {
		t.Errorf("Expected raw value 'c0a80101', got '%v'", valRaw)
	}

	valPretty := xmlLayer.GetFieldValue("src", false)
	if valPretty != container {
		t.Errorf("Expected pretty value to be the container itself")
	}

	// Test FieldNames (should be sanitized)
	names := xmlLayer.FieldNames()
	if len(names) != 1 || names[0] != "src" {
		t.Errorf("Expected FieldNames to be ['src'], got %v", names)
	}

	// Test XMLLayer with rawMode = true
	xmlLayerRaw := NewXMLLayer("ip", true)
	xmlLayerRaw.AddField(field1)
	fRaw := xmlLayerRaw.GetField("src")
	if fStr, ok := fRaw.(string); !ok || fStr != "192.168.1.1" {
		t.Errorf("Expected rawMode GetField to return default value string '192.168.1.1', got %v (%T)", fRaw, fRaw)
	}

	// Test fake-field-wrapper
	fakeLayer := NewXMLLayer("fake-field-wrapper", false)
	if fakeLayer.GetLayerName() != DataLayerName {
		t.Errorf("Expected 'fake-field-wrapper' to be converted to '%s', got '%s'", DataLayerName, fakeLayer.GetLayerName())
	}
}

func TestJSONLayer(t *testing.T) {
	// Test primitive data
	jsonLayer1 := NewJSONLayer("eth", "00:11:22:33:44:55", "eth", false)
	if jsonLayer1.Value != "00:11:22:33:44:55" {
		t.Errorf("Expected value '00:11:22:33:44:55', got '%v'", jsonLayer1.Value)
	}

	// Test map data
	mapData := map[string]interface{}{
		"ip.src": "192.168.1.1",
		"ip.dst": "192.168.1.2",
	}
	jsonLayer2 := NewJSONLayer("ip", mapData, "ip", false)
	if !jsonLayer2.HasField("src") {
		t.Errorf("Expected layer to have field 'src'")
	}
	if !jsonLayer2.HasField("dst") {
		t.Errorf("Expected layer to have field 'dst'")
	}

	srcVal := jsonLayer2.GetField("src")
	if srcVal != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%v'", srcVal)
	}

	// Test array data (duplicate layers)
	arrData := []interface{}{
		map[string]interface{}{"http.request.method": "GET"},
		map[string]interface{}{"http.request.method": "POST"},
	}
	jsonLayer3 := NewJSONLayer("http", arrData, "http", false)
	if len(jsonLayer3.DuplicateLayers) != 1 {
		t.Errorf("Expected 1 duplicate layer, got %d", len(jsonLayer3.DuplicateLayers))
	}
	if jsonLayer3.GetField("request.method") != "GET" {
		t.Errorf("Expected method 'GET', got '%v'", jsonLayer3.GetField("request.method"))
	}

	// Test FieldNames
	names := jsonLayer2.FieldNames()
	// Should extract src and dst
	if len(names) != 2 {
		t.Errorf("Expected 2 field names, got %d: %v", len(names), names)
	}

	// Test HasField dotted path (e.g. nested sublayers)
	nestedMap := map[string]interface{}{
		"http.request": map[string]interface{}{
			"http.request.method": "GET",
		},
	}
	jsonLayerNested := NewJSONLayer("http", nestedMap, "http", false)
	if !jsonLayerNested.HasField("request.method") {
		t.Errorf("Expected to resolve dotted path 'request.method'")
	}
}

func TestEKLayer(t *testing.T) {
	fieldsDict := map[string]interface{}{
		"ip_src": "192.168.1.1",
		"ip_dst": "192.168.1.2",
		"ip_ttl": "64", // should cast to int based on mapping
	}
	ekLayer := NewEKLayer("ip", fieldsDict)
	if ekLayer.GetLayerName() != "ip" {
		t.Errorf("Expected 'ip', got '%s'", ekLayer.GetLayerName())
	}

	// Test GetField
	src := ekLayer.GetField("src")
	if src != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%v'", src)
	}

	// Test casting
	ttl := ekLayer.GetField("ttl")
	if ttl != 64 {
		t.Errorf("Expected cast to int (64), got %v (%T)", ttl, ttl)
	}

	// Test GetFieldAsList
	srcList := ekLayer.GetFieldAsList("src")
	if len(srcList) != 1 || srcList[0] != "192.168.1.1" {
		t.Errorf("Expected list of size 1 with '192.168.1.1', got %v", srcList)
	}

	// Test FieldNames
	names := ekLayer.FieldNames()
	namesMap := make(map[string]bool)
	for _, n := range names {
		namesMap[n] = true
	}
	if !namesMap["src"] || !namesMap["dst"] || !namesMap["ttl"] {
		t.Errorf("Expected field prefixes src, dst, ttl, got %v", names)
	}

	// Test AllFieldNames
	allNames := ekLayer.AllFieldNames()
	if !allNames["src"] || !allNames["dst"] || !allNames["ttl"] {
		t.Errorf("Expected AllFieldNames to contain src, dst, ttl. Got: %v", allNames)
	}
}

func TestEKMultiField(t *testing.T) {
	fieldsDict := map[string]interface{}{
		"tcp_flags":            "0x0002",
		"tcp_flags_syn":        "1",
		"tcp_flags_ack":        "0",
		"tcp_flags_cwr_foo":    "0", // deep nesting
	}
	ekLayer := NewEKLayer("tcp", fieldsDict)

	// Since "tcp_flags" has "tcp_flags_syn" and "tcp_flags_ack" as subfields starting with tcp_flags_
	f := ekLayer.GetField("flags")
	if f == nil {
		t.Fatalf("Expected to get field 'flags'")
	}
	multiField, ok := f.(*EKMultiField)
	if !ok {
		t.Fatalf("Expected *EKMultiField, got %T", f)
	}

	if multiField.String() != "2" {
		t.Errorf("Expected string representation '2', got '%s'", multiField.String())
	}

	// Test subfield retrieval
	synVal := multiField.GetField("syn")
	if synVal != "1" {
		t.Errorf("Expected syn subfield to be '1', got '%v'", synVal)
	}

	// Test Subfields list
	subfields := multiField.Subfields()
	// Should be syn and ack. cwr_foo is deep nested.
	subfieldsMap := make(map[string]bool)
	for _, sf := range subfields {
		subfieldsMap[sf] = true
	}
	if !subfieldsMap["syn"] || !subfieldsMap["ack"] {
		t.Errorf("Expected subfields syn and ack to be returned, got %v", subfields)
	}
}

// TestPrettyPrint verifies PrettyPrint/String work on every concrete layer
// type. Each defines its own PrettyPrint because Go has no virtual dispatch:
// the promoted BaseLayer.PrettyPrint would call BaseLayer.prettyPrintLayerFields
// (which panics) rather than the concrete override.
func TestPrettyPrint(t *testing.T) {
	xmlLayer := NewXMLLayer("ip", false)
	xmlLayer.AddField(packet.NewLayerField("ip.src", "Source: 192.168.1.1", "c0a80101", "192.168.1.1", "no", "0", "0", ""))
	var xb bytes.Buffer
	xmlLayer.PrettyPrint(&xb)
	if !strings.Contains(xb.String(), "Layer IP:") {
		t.Errorf("XMLLayer.PrettyPrint missing header, got: %q", xb.String())
	}
	if xmlLayer.String() == "" {
		t.Errorf("XMLLayer.String() returned empty")
	}

	jsonLayer := NewJSONLayer("ip", map[string]interface{}{"ip.src": "192.168.1.1"}, "ip", false)
	var jb bytes.Buffer
	jsonLayer.PrettyPrint(&jb)
	if !strings.Contains(jb.String(), "Layer IP:") {
		t.Errorf("JSONLayer.PrettyPrint missing header, got: %q", jb.String())
	}

	ekLayer := NewEKLayer("ip", map[string]interface{}{"ip_src": "192.168.1.1"})
	var eb bytes.Buffer
	ekLayer.PrettyPrint(&eb)
	if !strings.Contains(eb.String(), "Layer IP:") {
		t.Errorf("EKLayer.PrettyPrint missing header, got: %q", eb.String())
	}
}
