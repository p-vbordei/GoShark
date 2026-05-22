package packet

import (
	"strings"
	"testing"
)

func TestPacketBasic(t *testing.T) {
	// Create a simple test packet
	p := &Packet{
		RawData: []byte{0x45, 0x00, 0x00, 0x3c},
	}

	// Test GetRawPacket
	rawData := p.GetRawPacket()
	if len(rawData) != 4 {
		t.Errorf("Expected raw data length of 4, got %d", len(rawData))
	}
}

// TestPacketJSONLayerOrderAndFrame verifies that real tshark -T json output
// (plain-string field values, ordered layers object) parses with layer order
// preserved and frame metadata populated.
func TestPacketJSONLayerOrderAndFrame(t *testing.T) {
	data := []byte(`[{"_index":"packets-x","_type":"doc","_source":{"layers":{
"frame":{"frame.number":"1","frame.len":"119","frame.cap_len":"119","frame.time_epoch":"1747997000.123456"},
"null":{"null.type":"2"},
"ip":{"ip.src":"127.0.0.1","ip.dst":"127.0.0.1"},
"tcp":{"tcp.srcport":"58894","tcp.dstport":"58968"},
"data":{"data.data":"00:01:02"}}}}]`)
	p, err := NewPacketFromJSON(data)
	if err != nil {
		t.Fatalf("NewPacketFromJSON: %v", err)
	}

	var names []string
	for _, l := range p.Layers {
		names = append(names, l.Name)
	}
	if got, want := strings.Join(names, ","), "frame,null,ip,tcp,data"; got != want {
		t.Errorf("layer order = %q, want %q", got, want)
	}
	if p.FrameNumber != "1" {
		t.Errorf("FrameNumber = %q, want %q", p.FrameNumber, "1")
	}
	if p.FrameLen != "119" {
		t.Errorf("FrameLen = %q, want %q", p.FrameLen, "119")
	}
	if p.HighestLayer() != "data" {
		t.Errorf("HighestLayer = %q, want %q", p.HighestLayer(), "data")
	}
	if p.TransportLayer() != "tcp" {
		t.Errorf("TransportLayer = %q, want %q", p.TransportLayer(), "tcp")
	}
}

// TestSniffTimeFormats verifies SniffTime accepts both a float epoch and an
// ISO-8601 timestamp (tshark renders absolute-time fields per the time-format
// preference, so frame.time_epoch is not always a float).
func TestSniffTimeFormats(t *testing.T) {
	pf := &Packet{FrameTimeEpoch: "1747997000.123456"}
	tf, err := pf.SniffTime()
	if err != nil {
		t.Fatalf("SniffTime(float): %v", err)
	}
	if tf.Unix() != 1747997000 {
		t.Errorf("SniffTime(float).Unix() = %d, want 1747997000", tf.Unix())
	}

	pi := &Packet{FrameTimeEpoch: "2025-05-23T10:43:13.726858000Z"}
	ti, err := pi.SniffTime()
	if err != nil {
		t.Fatalf("SniffTime(iso): %v", err)
	}
	if ti.UTC().Year() != 2025 {
		t.Errorf("SniffTime(iso).Year() = %d, want 2025", ti.UTC().Year())
	}

	if pf.SniffTimestamp() != "1747997000.123456" {
		t.Errorf("SniffTimestamp() = %q", pf.SniffTimestamp())
	}
}
