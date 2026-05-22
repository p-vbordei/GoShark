package packet_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"GoShark/packet"
)

func TestPacketRawData(t *testing.T) {
	// Create a test packet with raw data
	rawData, _ := hex.DecodeString("0800270a73f700045c5d3c0000400162f17f0000017f0000010035cb5b00000000000000005002200061020000")
	p := &packet.Packet{
		RawData: rawData,
	}

	// Test GetRawPacket
	gotRaw := p.GetRawPacket()
	assert.Equal(t, rawData, gotRaw, "GetRawPacket should return the raw packet data")

	// Test with nil raw data
	p = &packet.Packet{}
	gotRaw = p.GetRawPacket()
	assert.Nil(t, gotRaw, "GetRawPacket should return nil for a packet with no raw data")
}

func TestPacketWithLayers(t *testing.T) {
	// Create a test packet with layers
	ethLayer := packet.Layer{
		Name: "eth",
		Fields: map[string]interface{}{
			"eth.src": "00:11:22:33:44:55",
			"eth.dst": "aa:bb:cc:dd:ee:ff",
		},
		Offsets: map[string]*packet.FieldOffset{
			"eth.src": {Start: 6, Length: 6, Name: "eth.src"},
			"eth.dst": {Start: 0, Length: 6, Name: "eth.dst"},
		},
		Pos: 0,
		Len: 14,
	}

	ipLayer := packet.Layer{
		Name: "ip",
		Fields: map[string]interface{}{
			"ip.src": "192.168.1.1",
			"ip.dst": "192.168.1.2",
			"ip.len": 20,
		},
		Offsets: map[string]*packet.FieldOffset{
			"ip.src": {Start: 12, Length: 4, Name: "ip.src"},
			"ip.dst": {Start: 16, Length: 4, Name: "ip.dst"},
			"ip.len": {Start: 2, Length: 2, Name: "ip.len"},
		},
		Pos: 14,
		Len: 20,
	}

	p := &packet.Packet{
		Layers:  []packet.Layer{ethLayer, ipLayer},
		RawData: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02},
	}

	// Test GetLayer
	layer := p.GetLayer("eth")
	assert.NotNil(t, layer, "GetLayer should return the eth layer")
	assert.Equal(t, "eth", layer.Name, "Layer name should be eth")

	// Test GetLayerRawBytes
	ethRaw := p.GetLayerRawBytes("eth")
	assert.NotNil(t, ethRaw, "GetLayerRawBytes should return data for existing layer")
	assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00}, ethRaw, "GetLayerRawBytes should return the raw layer data")

	// Test GetFieldRawBytes
	srcRaw := p.GetFieldRawBytes("eth", "eth.src")
	assert.NotNil(t, srcRaw, "GetFieldRawBytes should return data for existing field")
	assert.Equal(t, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, srcRaw, "GetFieldRawBytes should return the raw field data")

	// Test field access
	ethLayerPtr := p.GetLayer("eth")
	srcValue := ethLayerPtr.GetField("eth.src")
	assert.Equal(t, "00:11:22:33:44:55", srcValue, "GetField should return the field value")

	// Test field int conversion
	ipLayerPtr := p.GetLayer("ip")
	ipLen, err := ipLayerPtr.GetFieldInt("ip.len")
	assert.NoError(t, err, "GetFieldInt should not error for numeric field")
	assert.Equal(t, int64(20), ipLen, "GetFieldInt should return the field value as int")

	// Test non-existent layer
	layer = p.GetLayer("tcp")
	assert.Nil(t, layer, "GetLayer should return nil for non-existent layer")

	// Test non-existent field
	tcpRaw := p.GetLayerRawBytes("tcp")
	assert.Nil(t, tcpRaw, "GetLayerRawBytes should return nil for non-existent layer")
}

func TestPacketUnmarshalJSONOffsets(t *testing.T) {
	jsonInput := []byte(`[
  {
    "_index": "packets-2025-05-23",
    "_source": {
      "layers": {
        "frame_raw": [
          "0200000045000073",
          0,
          8,
          0,
          1
        ],
        "frame": {
          "frame.number": "1",
          "frame.len": "8"
        },
        "ip_raw": [
          "45000073",
          4,
          4,
          0,
          1
        ],
        "ip": {
          "ip.src_raw": [
            "45000073",
            4,
            4,
            0,
            1
          ],
          "ip.src": "127.0.0.1"
        }
      }
    }
  }
]`)

	p, err := packet.NewPacketFromJSON(jsonInput)
	assert.NoError(t, err, "NewPacketFromJSON should succeed")
	assert.NotNil(t, p, "Packet should not be nil")

	// Verify raw packet data was extracted
	expectedRaw := []byte{0x02, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x73}
	assert.Equal(t, expectedRaw, p.RawData, "Packet raw data should match expected bytes")

	// Verify only two layers exist (frame, ip), no _raw layers
	assert.Equal(t, 2, len(p.Layers), "Packet should have exactly 2 layers")
	assert.True(t, p.HasLayer("frame"), "Packet should have frame layer")
	assert.True(t, p.HasLayer("ip"), "Packet should have ip layer")

	frameLayer := p.GetLayer("frame")
	assert.Equal(t, 0, frameLayer.Pos, "Frame layer position should be 0")
	assert.Equal(t, 8, frameLayer.Len, "Frame layer length should be 8")

	ipLayer := p.GetLayer("ip")
	assert.Equal(t, 4, ipLayer.Pos, "IP layer position should be 4")
	assert.Equal(t, 4, ipLayer.Len, "IP layer length should be 4")

	// Verify layer raw bytes
	ipRaw := p.GetLayerRawBytes("ip")
	assert.Equal(t, []byte{0x45, 0x00, 0x00, 0x73}, ipRaw, "IP layer raw bytes should be extracted correctly")

	// Verify field offset and raw bytes
	ipSrcRaw := p.GetFieldRawBytes("ip", "ip.src")
	assert.Equal(t, []byte{0x45, 0x00, 0x00, 0x73}, ipSrcRaw, "IP src field raw bytes should be extracted correctly")
}
