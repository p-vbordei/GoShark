package packet

import (
	"testing"
	"time"
)

func TestSessionKey(t *testing.T) {
	// Create a session key
	key := SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  "1234",
		DstPort:  "80",
	}

	// Test String method
	keyStr := key.String()
	expected := "tcp:192.168.1.1:1234-192.168.1.2:80"
	if keyStr != expected {
		t.Errorf("Expected key string '%s', got '%s'", expected, keyStr)
	}

	// Test Normalized method with source IP > destination IP
	key = SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.2", // Greater than DstIP
		DstIP:    "192.168.1.1",
		SrcPort:  "80",
		DstPort:  "1234",
	}

	normKey := key.Normalized()
	if normKey.Protocol != "tcp" {
		t.Errorf("Protocol should remain unchanged, got %s", normKey.Protocol)
	}
	if normKey.SrcIP != "192.168.1.1" {
		t.Errorf("Source IP should be swapped, got %s", normKey.SrcIP)
	}
	if normKey.DstIP != "192.168.1.2" {
		t.Errorf("Destination IP should be swapped, got %s", normKey.DstIP)
	}
	if normKey.SrcPort != "1234" {
		t.Errorf("Source port should be swapped, got %s", normKey.SrcPort)
	}
	if normKey.DstPort != "80" {
		t.Errorf("Destination port should be swapped, got %s", normKey.DstPort)
	}
}

func TestSession(t *testing.T) {
	// Create a session key
	key := SessionKey{
		Protocol: "tcp",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  "1234",
		DstPort:  "80",
	}

	// Create a session
	session := NewSession(key)
	if session.Key != key {
		t.Errorf("Session key should match the provided key")
	}
	if session.GetPacketCount() != 0 {
		t.Errorf("Initial packet count should be 0, got %d", session.GetPacketCount())
	}
	if session.State != "new" {
		t.Errorf("Initial session state should be 'new', got '%s'", session.State)
	}

	// Create a mock packet with TCP layer
	tcpLayer := Layer{
		Name: "tcp",
		Fields: map[string]interface{}{
			"tcp.srcport": "1234",
			"tcp.dstport": "80",
			"tcp.flags": "SYN",
		},
	}

	frameLayer := Layer{
		Name: "frame",
		Fields: map[string]interface{}{
			"frame.time_epoch": float64(time.Now().Unix()),
		},
	}

	p := &Packet{
		Layers: []Layer{tcpLayer, frameLayer},
	}

	// Add packet to session
	session.AddPacket(p)
	if session.GetPacketCount() != 1 {
		t.Errorf("Packet count should be 1 after adding a packet, got %d", session.GetPacketCount())
	}
	if session.State != "syn_sent" {
		t.Errorf("Session state should be 'syn_sent' after SYN packet, got '%s'", session.State)
	}
}

func TestSessionTracker(t *testing.T) {
	// Create a session tracker
	tracker := NewSessionTracker()
	if tracker.GetSessionCount() != 0 {
		t.Errorf("Initial session count should be 0, got %d", tracker.GetSessionCount())
	}

	// Create a mock packet with IP and TCP layers
	ipLayer := Layer{
		Name: "ip",
		Fields: map[string]interface{}{
			"ip.src": "192.168.1.1",
			"ip.dst": "192.168.1.2",
		},
	}

	tcpLayer := Layer{
		Name: "tcp",
		Fields: map[string]interface{}{
			"tcp.srcport": "1234",
			"tcp.dstport": "80",
			"tcp.flags": "SYN",
		},
	}

	frameLayer := Layer{
		Name: "frame",
		Fields: map[string]interface{}{
			"frame.time_epoch": float64(time.Now().Unix()),
		},
	}

	p := &Packet{
		Layers: []Layer{ipLayer, tcpLayer, frameLayer},
	}

	// Add packet to tracker
	tracker.AddPacket(p)
	if tracker.GetSessionCount() != 1 {
		t.Errorf("Session count should be 1 after adding a packet, got %d", tracker.GetSessionCount())
	}
}
