package capture

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"GoShark/packet"
	"GoShark/tshark"
)

// testPcap is the bundled 5-packet loopback/TCP capture, relative to capture/.
const testPcap = "../test.pcap"

// requireTShark skips the test cleanly when tshark is not installed, so the
// suite stays green on machines without Wireshark.
func requireTShark(t *testing.T) {
	t.Helper()
	if _, err := tshark.FindTShark(); err != nil {
		t.Skipf("tshark not installed; skipping integration test: %v", err)
	}
}

// collect drains every packet a capture produces over test.pcap.
func collect(t *testing.T, fc *FileCapture) []*packet.Packet {
	t.Helper()
	var pkts []*packet.Packet
	err := fc.ApplyOnPackets(func(p *packet.Packet) bool {
		pkts = append(pkts, p)
		return false
	}, context.Background())
	require.NoError(t, err)
	return pkts
}

func TestFileCaptureIntegrationJSON(t *testing.T) {
	requireTShark(t)

	fc, err := NewFileCapture(testPcap)
	require.NoError(t, err)

	pkts := collect(t, fc)
	require.Len(t, pkts, 5, "test.pcap has 5 packets")

	first := pkts[0]
	require.Equal(t, "1", first.FrameNumber)
	require.NotEmpty(t, first.FrameLen)
	require.Equal(t, "frame", first.Layers[0].Name, "frame must be the first layer")
	require.Equal(t, "tcp", first.TransportLayer())

	st, err := first.SniffTime()
	require.NoError(t, err)
	require.False(t, st.IsZero(), "sniff time must be populated")

	// Frame numbers must be sequential 1..5 in document order.
	for i, p := range pkts {
		require.Equal(t, []string{"1", "2", "3", "4", "5"}[i], p.FrameNumber)
	}
}

func TestFileCaptureIntegrationXML(t *testing.T) {
	requireTShark(t)

	fc, err := NewFileCapture(testPcap, WithUseJSON(false))
	require.NoError(t, err)

	pkts := collect(t, fc)
	require.Len(t, pkts, 5)

	first := pkts[0]
	require.Equal(t, "1", first.FrameNumber)
	require.NotEmpty(t, first.FrameLen)
	for _, l := range first.Layers {
		require.NotEqual(t, "fake-field-wrapper", l.Name)
		require.NotEqual(t, "geninfo", l.Name)
	}
	require.Equal(t, "frame", first.Layers[0].Name)
}

func TestInMemCaptureIntegration(t *testing.T) {
	requireTShark(t)

	// A minimal Ethernet + IPv4 + TCP frame.
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
		0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // src MAC
		0x08, 0x00, // EtherType IPv4
		0x45, 0x00, 0x00, 0x3c, 0x7c, 0x3c, 0x40, 0x00, 0x40, 0x06,
		0x65, 0x7a, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01,
		0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xbd, 0x86, 0x00, 0x00,
	}

	cap := NewInMemCapture(WithLinkType(LinkTypeEthernet))
	defer cap.Close()

	sniffTime := time.Now()
	p, err := cap.ParsePacket(frame, &sniffTime)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.True(t, p.HasLayer("ip"), "parsed packet should have an ip layer")
	require.True(t, p.HasLayer("tcp"), "parsed packet should have a tcp layer")
	require.Equal(t, "tcp", p.TransportLayer())
}

func TestCaptureLoadPackets(t *testing.T) {
	requireTShark(t)

	fc, err := NewFileCapture(testPcap)
	require.NoError(t, err)

	pkts, err := fc.LoadPackets(context.Background(), 3)
	require.NoError(t, err)
	require.Len(t, pkts, 3, "LoadPackets(3) should buffer exactly 3 packets")
	require.Equal(t, 3, fc.Len())
	require.Equal(t, "1", fc.Get(0).FrameNumber)
	require.Equal(t, "2", fc.Get(1).FrameNumber)
	require.Nil(t, fc.Get(99), "out-of-range index returns nil")

	// count == 0 means "all packets".
	all, err := fc.LoadPackets(context.Background(), 0)
	require.NoError(t, err)
	require.Len(t, all, 5)
}

func TestPipeCaptureIntegration(t *testing.T) {
	requireTShark(t)

	f, err := os.Open(testPcap)
	require.NoError(t, err)
	defer f.Close()

	pc := NewPipeCapture(f)
	var pkts []*packet.Packet
	err = pc.ApplyOnPackets(func(p *packet.Packet) bool {
		pkts = append(pkts, p)
		return false
	}, context.Background(), pc.Start)
	require.NoError(t, err)
	require.Len(t, pkts, 5, "pipe capture should yield all 5 packets of test.pcap")
	require.Equal(t, "1", pkts[0].FrameNumber)
}
