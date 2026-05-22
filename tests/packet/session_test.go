package packet_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"GoShark/packet"
)

func TestSessionKey(t *testing.T) {
	// Create a session key
	key := packet.SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  "1234",
		DstPort:  "80",
	}

	// Test String method
	keyStr := key.String()
	expected := "tcp:192.168.1.1:1234-192.168.1.2:80"
	assert.Equal(t, expected, keyStr, "Session key string representation should match expected format")

	// Test Normalized method with source IP > destination IP
	key = packet.SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.2", // Greater than DstIP
		DstIP:    "192.168.1.1",
		SrcPort:  "80",
		DstPort:  "1234",
	}

	normKey := key.Normalized()
	assert.Equal(t, "tcp", normKey.Protocol, "Protocol should remain unchanged")
	assert.Equal(t, "192.168.1.1", normKey.SrcIP, "Source IP should be swapped with destination IP")
	assert.Equal(t, "192.168.1.2", normKey.DstIP, "Destination IP should be swapped with source IP")
	assert.Equal(t, "1234", normKey.SrcPort, "Source port should be swapped with destination port")
	assert.Equal(t, "80", normKey.DstPort, "Destination port should be swapped with source port")

	// Test Normalized method with equal IPs but source port > destination port
	key = packet.SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.1",
		SrcPort:  "8080", // Greater than DstPort
		DstPort:  "80",
	}

	normKey = key.Normalized()
	assert.Equal(t, "tcp", normKey.Protocol, "Protocol should remain unchanged")
	assert.Equal(t, "192.168.1.1", normKey.SrcIP, "Source IP should remain unchanged")
	assert.Equal(t, "192.168.1.1", normKey.DstIP, "Destination IP should remain unchanged")
	assert.Equal(t, "80", normKey.SrcPort, "Source port should be swapped with destination port")
	assert.Equal(t, "8080", normKey.DstPort, "Destination port should be swapped with source port")
}

func TestSession(t *testing.T) {
	// Create a session key
	key := packet.SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  "1234",
		DstPort:  "80",
	}

	// Create a session
	session := packet.NewSession(key)
	assert.Equal(t, key, session.Key, "Session key should match the provided key")
	assert.Equal(t, 0, session.GetPacketCount(), "Initial packet count should be 0")
	assert.Equal(t, "new", session.State, "Initial session state should be 'new'")

	// Create a mock packet with TCP layer
	tcpLayer := packet.Layer{
		Name: "tcp",
		Fields: map[string]interface{}{
			"tcp.srcport": "1234",
			"tcp.dstport": "80",
			"tcp.flags": "SYN",
		},
	}

	frameLayer := packet.Layer{
		Name: "frame",
		Fields: map[string]interface{}{
			"frame.time_epoch": float64(time.Now().Unix()),
		},
	}

	p := &packet.Packet{
		Layers: []packet.Layer{tcpLayer, frameLayer},
	}

	// Add packet to session
	session.AddPacket(p)
	assert.Equal(t, 1, session.GetPacketCount(), "Packet count should be 1 after adding a packet")
	assert.Equal(t, "syn_sent", session.State, "Session state should be 'syn_sent' after SYN packet")

	// Add a SYN+ACK packet
	tcpLayer2 := packet.Layer{
		Name: "tcp",
		Fields: map[string]interface{}{
			"tcp.srcport": "80",
			"tcp.dstport": "1234",
			"tcp.flags": "SYN+ACK",
		},
	}

	frameLayer2 := packet.Layer{
		Name: "frame",
		Fields: map[string]interface{}{
			"frame.time_epoch": float64(time.Now().Unix()),
		},
	}

	p2 := &packet.Packet{
		Layers: []packet.Layer{tcpLayer2, frameLayer2},
	}

	session.AddPacket(p2)
	assert.Equal(t, 2, session.GetPacketCount(), "Packet count should be 2 after adding another packet")
	assert.Equal(t, "syn_received", session.State, "Session state should be 'syn_received' after SYN+ACK packet")

	// Test session duration
	duration := session.GetDuration()
	assert.GreaterOrEqual(t, duration, int64(0), "Session duration should be non-negative")
}

func TestSessionTracker(t *testing.T) {
	// Create a session tracker
	tracker := packet.NewSessionTracker()
	assert.Equal(t, 0, tracker.GetSessionCount(), "Initial session count should be 0")

	// Create a mock packet with IP and TCP layers
	ipLayer := packet.Layer{
		Name: "ip",
		Fields: map[string]interface{}{
			"ip.src": "192.168.1.1",
			"ip.dst": "192.168.1.2",
		},
	}

	tcpLayer := packet.Layer{
		Name: "tcp",
		Fields: map[string]interface{}{
			"tcp.srcport": "1234",
			"tcp.dstport": "80",
			"tcp.flags": "SYN",
		},
	}

	frameLayer := packet.Layer{
		Name: "frame",
		Fields: map[string]interface{}{
			"frame.time_epoch": float64(time.Now().Unix()),
		},
	}

	p := &packet.Packet{
		Layers: []packet.Layer{ipLayer, tcpLayer, frameLayer},
	}

	// Add packet to tracker
	tracker.AddPacket(p)
	assert.Equal(t, 1, tracker.GetSessionCount(), "Session count should be 1 after adding a packet")

	// Create a session key for lookup
	key := packet.SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  "1234",
		DstPort:  "80",
	}

	// Get session from tracker
	session := tracker.GetSession(key)
	assert.NotNil(t, session, "GetSession should return a session for the given key")
	assert.Equal(t, 1, session.GetPacketCount(), "Session should have 1 packet")

	// Add a packet in the reverse direction (response)
	ipLayer2 := packet.Layer{
		Name: "ip",
		Fields: map[string]interface{}{
			"ip.src": "192.168.1.2",
			"ip.dst": "192.168.1.1",
		},
	}

	tcpLayer2 := packet.Layer{
		Name: "tcp",
		Fields: map[string]interface{}{
			"tcp.srcport": "80",
			"tcp.dstport": "1234",
			"tcp.flags": "SYN+ACK",
		},
	}

	frameLayer2 := packet.Layer{
		Name: "frame",
		Fields: map[string]interface{}{
			"frame.time_epoch": float64(time.Now().Unix()),
		},
	}

	p2 := &packet.Packet{
		Layers: []packet.Layer{ipLayer2, tcpLayer2, frameLayer2},
	}

	// Add packet to tracker
	tracker.AddPacket(p2)
	// Session count should still be 1 since this is part of the same session
	assert.Equal(t, 1, tracker.GetSessionCount(), "Session count should still be 1 after adding a response packet")

	// Get all sessions
	sessions := tracker.GetAllSessions()
	assert.Equal(t, 1, len(sessions), "GetAllSessions should return 1 session")
	assert.Equal(t, 2, sessions[0].GetPacketCount(), "Session should have 2 packets")
}
