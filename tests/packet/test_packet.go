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
		Layers: []packet.Layer{ethLayer, ipLayer},
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
