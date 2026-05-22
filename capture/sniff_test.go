package capture

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/p-vbordei/GoShark/packet"
	"github.com/p-vbordei/GoShark/packet/layers"
)

func TestSniffStreamJSON(t *testing.T) {
	jsonData := `[
		{
			"_index": "packets-1",
			"_source": {
				"layers": {
					"ip": {
						"ip.src": "192.168.1.1"
					}
				}
			}
		},
		{
			"_index": "packets-2",
			"_source": {
				"layers": {
					"tcp": {
						"tcp.srcport": "80"
					}
				}
			}
		}
	]`

	c := NewCapture(WithUseJSON(true))
	stdout := io.NopCloser(strings.NewReader(jsonData))
	stderr := io.NopCloser(strings.NewReader(""))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	packetsChan, err := c.sniffStream(ctx, stdout, stderr)
	assert.NoError(t, err)

	// Read first packet
	var p1 *packet.Packet
	select {
	case p1 = <-packetsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for first packet")
	}
	assert.NotNil(t, p1)
	assert.True(t, p1.HasLayer("ip"))
	ipLayer := p1.GetLayer("ip")
	assert.NotNil(t, ipLayer.JSONLayer)
	jsonLayer := ipLayer.JSONLayer.(*layers.JSONLayer)
	assert.Equal(t, "192.168.1.1", jsonLayer.GetField("src"))

	// Read second packet
	var p2 *packet.Packet
	select {
	case p2 = <-packetsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for second packet")
	}
	assert.NotNil(t, p2)
	assert.True(t, p2.HasLayer("tcp"))
}

func TestSniffStreamXML(t *testing.T) {
	xmlData := `<pdml>
<packet num="1">
  <proto name="ip">
    <field name="ip.src" show="192.168.1.1"/>
  </proto>
</packet>
<packet num="2">
  <proto name="tcp">
    <field name="tcp.srcport" show="80"/>
  </proto>
</packet>
</pdml>`

	c := NewCapture(WithUseJSON(false))
	stdout := io.NopCloser(strings.NewReader(xmlData))
	stderr := io.NopCloser(strings.NewReader(""))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	packetsChan, err := c.sniffStream(ctx, stdout, stderr)
	assert.NoError(t, err)

	// Read first packet
	var p1 *packet.Packet
	select {
	case p1 = <-packetsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for first packet")
	}
	assert.NotNil(t, p1)
	assert.True(t, p1.HasLayer("ip"))
	ipLayer := p1.GetLayer("ip")
	assert.NotNil(t, ipLayer.XMLLayer)
	xmlLayer := ipLayer.XMLLayer.(*layers.XMLLayer)
	fVal := xmlLayer.GetFieldValue("src", false)
	assert.NotNil(t, fVal)

	// Read second packet
	var p2 *packet.Packet
	select {
	case p2 = <-packetsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for second packet")
	}
	assert.NotNil(t, p2)
	assert.True(t, p2.HasLayer("tcp"))
}

func TestApplyOnPackets(t *testing.T) {
	jsonData := `[
		{
			"_index": "packets-1",
			"_source": {
				"layers": {
					"ip": {
						"ip.src": "192.168.1.1"
					}
				}
			}
		},
		{
			"_index": "packets-2",
			"_source": {
				"layers": {
					"tcp": {
						"tcp.srcport": "80"
					}
				}
			}
		}
	]`

	c := NewCapture(WithUseJSON(true))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var receivedPackets []*packet.Packet

	// Callback returns false to keep receiving, true to stop
	callback := func(p *packet.Packet) bool {
		receivedPackets = append(receivedPackets, p)
		return len(receivedPackets) >= 1 // Stop after 1 packet
	}

	startFunc := func() (io.ReadCloser, io.ReadCloser, error) {
		stdout := io.NopCloser(strings.NewReader(jsonData))
		stderr := io.NopCloser(strings.NewReader(""))
		return stdout, stderr, nil
	}

	err := c.ApplyOnPackets(callback, ctx, startFunc)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(receivedPackets))
	assert.True(t, receivedPackets[0].HasLayer("ip"))
}

func TestSniffStreamCancellation(t *testing.T) {
	// A JSON stream that never ends (blocks on read)
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	c := NewCapture(WithUseJSON(true))
	stderr := io.NopCloser(strings.NewReader(""))

	ctx, cancel := context.WithCancel(context.Background())

	// Write start of JSON array so decoder initialized
	go func() {
		pw.Write([]byte("[\n"))
	}()

	packetsChan, err := c.sniffStream(ctx, pr, stderr)
	assert.NoError(t, err)

	// Cancel context to stop sniffing
	cancel()

	// The channel should close and not block forever
	select {
	case _, ok := <-packetsChan:
		assert.False(t, ok, "Channel should be closed")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for channel closure after cancellation")
	}
}
