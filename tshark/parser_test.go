package tshark

import (
	"strings"
	"testing"
	"time"

	"GoShark/packet/layers"
)

func TestJSONParser(t *testing.T) {
	jsonData := `[
		{
			"_index": "packets-2021-05-03",
			"_type": "doc",
			"_score": null,
			"_source": {
				"layers": {
					"frame": {
						"frame.number": [{"value": "1"}],
						"frame.len": [{"value": "60"}],
						"frame.time": [{"value": "May 3, 2021 18:40:00.000000000 UTC"}]
					},
					"ip": {
						"ip.src": "192.168.1.1",
						"ip.dst": "192.168.1.2"
					}
				}
			}
		}
	]`

	parser := NewJSONParser(WithIncludeRaw(false))
	pkts, err := parser.ParsePackets(strings.NewReader(jsonData))
	if err != nil {
		t.Fatalf("ParsePackets failed: %v", err)
	}

	if len(pkts) != 1 {
		t.Fatalf("Expected 1 packet, got %d", len(pkts))
	}

	pkt := pkts[0]
	if pkt.FrameNumber != "1" || pkt.FrameLen != "60" {
		t.Errorf("Expected FrameNumber '1' and FrameLen '60', got '%s' and '%s'", pkt.FrameNumber, pkt.FrameLen)
	}

	// Verify JSONLayer is populated
	ipLayer := pkt.GetLayer("ip")
	if ipLayer == nil {
		t.Fatalf("Expected ip layer")
	}
	if ipLayer.JSONLayer == nil {
		t.Errorf("Expected JSONLayer to be populated on ip layer")
	}
	jsonLayer, ok := ipLayer.JSONLayer.(*layers.JSONLayer)
	if !ok {
		t.Fatalf("Expected JSONLayer type, got %T", ipLayer.JSONLayer)
	}
	if jsonLayer.GetField("src") != "192.168.1.1" {
		t.Errorf("Expected src '192.168.1.1', got '%v'", jsonLayer.GetField("src"))
	}

	// Test ParseSinglePacket
	singlePkt, err := parser.ParseSinglePacket(jsonData)
	if err != nil {
		t.Fatalf("ParseSinglePacket failed with array: %v", err)
	}
	if singlePkt.FrameNumber != "1" {
		t.Errorf("Expected FrameNumber '1', got '%s'", singlePkt.FrameNumber)
	}

	// Test ParseSinglePacket with raw object (no array wrapper)
	objectData := `{
		"_index": "packets-2021-05-03",
		"_source": {
			"layers": {
				"ip": {
					"ip.src": "192.168.1.1"
				}
			}
		}
	}`
	singlePktObj, err := parser.ParseSinglePacket(objectData)
	if err != nil {
		t.Fatalf("ParseSinglePacket failed with object: %v", err)
	}
	if !singlePktObj.HasLayer("ip") {
		t.Errorf("Expected packet to have ip layer")
	}

	// Test convenience functions
	pktsConv, err := ParseTSharkJSONString(jsonData, false)
	if err != nil {
		t.Fatalf("ParseTSharkJSONString failed: %v", err)
	}
	if len(pktsConv) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(pktsConv))
	}
}

func TestXMLParser(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="utf-8"?>
<pdml version="0" creator="wireshark/3.4.4">
<packet num="1">
  <proto name="frame" showname="Frame 1: 60 bytes on wire">
    <field name="frame.time_epoch" show="1620000000.000000000"/>
    <field name="frame.time" show="May 3, 2021 18:40:00.000000000 UTC"/>
    <field name="frame.len" show="60"/>
    <field name="frame.cap_len" show="60"/>
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4">
    <field name="ip.src" showname="Source: 192.168.1.1" value="c0a80101" show="192.168.1.1"/>
    <field name="ip.dst" showname="Destination: 192.168.1.2" value="c0a80102" show="192.168.1.2"/>
  </proto>
</packet>
</pdml>`

	parser := NewXMLParser(WithXMLIncludeRaw(true))
	pkts, err := parser.ParsePackets(strings.NewReader(xmlData))
	if err != nil {
		t.Fatalf("ParsePackets failed: %v", err)
	}

	if len(pkts) != 1 {
		t.Fatalf("Expected 1 packet, got %d", len(pkts))
	}

	pkt := pkts[0]
	if pkt.FrameNumber != "1" || pkt.FrameLen != "60" || pkt.FrameTimeEpoch != "1620000000.000000000" {
		t.Errorf("Expected FrameNumber '1', FrameLen '60', FrameTimeEpoch '1620000000.000000000'. Got %s, %s, %s",
			pkt.FrameNumber, pkt.FrameLen, pkt.FrameTimeEpoch)
	}

	// Verify XMLLayer is populated
	ipLayer := pkt.GetLayer("ip")
	if ipLayer == nil {
		t.Fatalf("Expected ip layer")
	}
	if ipLayer.XMLLayer == nil {
		t.Errorf("Expected XMLLayer to be populated on ip layer")
	}
	xmlLayer, ok := ipLayer.XMLLayer.(*layers.XMLLayer)
	if !ok {
		t.Fatalf("Expected XMLLayer type, got %T", ipLayer.XMLLayer)
	}
	fVal := xmlLayer.GetFieldValue("src", false)
	if fVal == nil {
		t.Fatalf("Expected to get field src")
	}

	// Test ParseSinglePacket
	singlePkt, err := parser.ParseSinglePacket(xmlData)
	if err != nil {
		t.Fatalf("ParseSinglePacket failed: %v", err)
	}
	if singlePkt.FrameNumber != "1" {
		t.Errorf("Expected FrameNumber '1', got '%s'", singlePkt.FrameNumber)
	}

	// Test convenience functions
	pktsConv, err := ParseTSharkXMLString(xmlData, false)
	if err != nil {
		t.Fatalf("ParseTSharkXMLString failed: %v", err)
	}
	if len(pktsConv) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(pktsConv))
	}
}

// TestXMLDropsFakeFieldWrapper verifies that the PDML "fake-field-wrapper"
// artifact layer is filtered out, as pyshark does.
func TestXMLDropsFakeFieldWrapper(t *testing.T) {
	xmlData := `<pdml><packet num="1">
<proto name="frame"><field name="frame.number" show="1"/><field name="frame.len" show="119"/></proto>
<proto name="ip"><field name="ip.src" show="127.0.0.1"/></proto>
<proto name="tcp"><field name="tcp.srcport" show="58894"/></proto>
<proto name="fake-field-wrapper"><field name="text" show="junk"/></proto>
</packet></pdml>`

	parser := NewXMLParser()
	pkts, err := parser.ParsePackets(strings.NewReader(xmlData))
	if err != nil {
		t.Fatalf("ParsePackets failed: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("Expected 1 packet, got %d", len(pkts))
	}

	for _, l := range pkts[0].Layers {
		if l.Name == "fake-field-wrapper" {
			t.Errorf("fake-field-wrapper layer should have been dropped")
		}
	}
	if pkts[0].FrameNumber != "1" {
		t.Errorf("FrameNumber = %q, want %q", pkts[0].FrameNumber, "1")
	}
	if pkts[0].HighestLayer() != "tcp" {
		t.Errorf("HighestLayer = %q, want %q", pkts[0].HighestLayer(), "tcp")
	}
}

func TestEKParser(t *testing.T) {
	// EK document format uses JSON lines
	// 1620067200 is 2021-05-03T18:40:00Z
	ekData := `{"_index":{"_type":"doc"},"_source":{"layers":{"frame":{"frame_number":"1","frame_len":"60","frame_time_epoch":"1620067200.000000000"},"ip":{"ip_src":"192.168.1.1","ip_dst":"192.168.1.2"}},"timestamp":"2021-05-03T18:40:00Z"}}`

	parser := NewEKParser(WithEKIncludeRaw(false))
	pkts, err := parser.ParsePackets(strings.NewReader(ekData))
	if err != nil {
		t.Fatalf("ParsePackets failed: %v", err)
	}

	if len(pkts) != 1 {
		t.Fatalf("Expected 1 packet, got %d", len(pkts))
	}

	pkt := pkts[0]
	if pkt.FrameNumber != "1" || pkt.FrameLen != "60" || pkt.FrameTimeEpoch != "1620067200.000000000" {
		t.Errorf("Expected FrameNumber '1', FrameLen '60', FrameTimeEpoch '1620067200.000000000'. Got %s, %s, %s",
			pkt.FrameNumber, pkt.FrameLen, pkt.FrameTimeEpoch)
	}

	// Check timestamp parsing
	expectedTime, _ := time.Parse(time.RFC3339, "2021-05-03T18:40:00Z")
	tVal, err := pkt.SniffTime()
	if err != nil {
		t.Fatalf("SniffTime failed: %v", err)
	}
	if !tVal.UTC().Equal(expectedTime) {
		t.Errorf("Expected SniffTime %v, got %v", expectedTime, tVal.UTC())
	}

	// Verify EKLayer is populated
	ipLayer := pkt.GetLayer("ip")
	if ipLayer == nil {
		t.Fatalf("Expected ip layer")
	}
	if ipLayer.EKLayer == nil {
		t.Errorf("Expected EKLayer to be populated on ip layer")
	}
	ekLayer, ok := ipLayer.EKLayer.(*layers.EKLayer)
	if !ok {
		t.Fatalf("Expected EKLayer type, got %T", ipLayer.EKLayer)
	}
	if ekLayer.GetField("src") != "192.168.1.1" {
		t.Errorf("Expected src '192.168.1.1', got '%v'", ekLayer.GetField("src"))
	}

	// Test ParseSinglePacket
	singlePkt, err := parser.ParseSinglePacket(ekData)
	if err != nil {
		t.Fatalf("ParseSinglePacket failed: %v", err)
	}
	if singlePkt.FrameNumber != "1" {
		t.Errorf("Expected FrameNumber '1', got '%s'", singlePkt.FrameNumber)
	}

	// Test convenience functions
	pktsConv, err := ParseTSharkEKString(ekData, false)
	if err != nil {
		t.Fatalf("ParseTSharkEKString failed: %v", err)
	}
	if len(pktsConv) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(pktsConv))
	}
}
