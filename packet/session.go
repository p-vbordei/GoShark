package packet

import (
	"fmt"
	"strings"
	"sync"
)

// SessionKey represents a unique identifier for a network session or conversation.
type SessionKey struct {
	Protocol string // Transport protocol (e.g., "tcp", "udp")
	SrcIP    string // Source IP address
	DstIP    string // Destination IP address
	SrcPort  string // Source port
	DstPort  string // Destination port
}

// String returns a string representation of the SessionKey.
func (k SessionKey) String() string {
	return fmt.Sprintf("%s:%s:%s-%s:%s", k.Protocol, k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

// Normalized returns a normalized version of the SessionKey where source and destination
// are ordered to ensure that the same session is identified regardless of direction.
func (k SessionKey) Normalized() SessionKey {
	// For TCP/UDP sessions, we want to normalize the key so that the "smaller" address
	// is always the source. This ensures that the same session is identified regardless
	// of packet direction.
	if k.Protocol == "tcp" || k.Protocol == "udp" {
		// Compare IPs first
		cmpIP := strings.Compare(k.SrcIP, k.DstIP)
		if cmpIP > 0 {
			// Swap source and destination
			return SessionKey{
				Protocol: k.Protocol,
				SrcIP:    k.DstIP,
				DstIP:    k.SrcIP,
				SrcPort:  k.DstPort,
				DstPort:  k.SrcPort,
			}
		} else if cmpIP == 0 {
			// If IPs are equal, compare ports
			cmpPort := strings.Compare(k.SrcPort, k.DstPort)
			if cmpPort > 0 {
				// Swap source and destination
				return SessionKey{
					Protocol: k.Protocol,
					SrcIP:    k.DstIP,
					DstIP:    k.SrcIP,
					SrcPort:  k.DstPort,
					DstPort:  k.SrcPort,
				}
			}
		}
	}
	// For other protocols or if no swap needed, return as is
	return k
}

// Session represents a network session or conversation between two endpoints.
type Session struct {
	Key     SessionKey  // Unique identifier for the session
	Packets []*Packet   // Packets belonging to this session
	Started int64       // Timestamp when the session started (Unix timestamp)
	Ended   int64       // Timestamp when the session ended (Unix timestamp, 0 if ongoing)
	State   string      // Session state (e.g., "established", "closed")
	Mutex   sync.RWMutex // Mutex for thread-safe operations
}

// NewSession creates a new Session with the given key.
func NewSession(key SessionKey) *Session {
	return &Session{
		Key:     key,
		Packets: make([]*Packet, 0),
		State:   "new",
	}
}

// AddPacket adds a packet to the session and updates session timestamps.
func (s *Session) AddPacket(packet *Packet) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Add packet to the session
	s.Packets = append(s.Packets, packet)

	// Update session timestamps
	ts, err := packet.SniffTime()
	if err == nil {
		unixTime := ts.Unix()
		if s.Started == 0 || unixTime < s.Started {
			s.Started = unixTime
		}
		if unixTime > s.Ended {
			s.Ended = unixTime
		}
	}

	// Update session state based on TCP flags if this is a TCP packet
	if tcpLayer := packet.GetLayer("tcp"); tcpLayer != nil {
		s.updateTCPState(tcpLayer)
	}
}

// updateTCPState updates the session state based on TCP flags.
func (s *Session) updateTCPState(tcpLayer *Layer) {
	// Get TCP flags
	flags, ok := tcpLayer.Fields["tcp.flags"]
	if !ok {
		return
	}

	// Convert flags to string for easier handling
	flagsStr := fmt.Sprintf("%v", flags)

	// Update state based on flags
	if strings.Contains(flagsStr, "SYN") && !strings.Contains(flagsStr, "ACK") {
		// SYN without ACK indicates connection initiation
		s.State = "syn_sent"
	} else if strings.Contains(flagsStr, "SYN") && strings.Contains(flagsStr, "ACK") {
		// SYN+ACK indicates connection establishment in progress
		s.State = "syn_received"
	} else if strings.Contains(flagsStr, "ACK") && s.State == "syn_received" {
		// ACK after SYN+ACK indicates established connection
		s.State = "established"
	} else if strings.Contains(flagsStr, "FIN") {
		// FIN indicates connection termination
		if s.State == "fin_wait_1" || s.State == "fin_wait_2" {
			s.State = "closing"
		} else {
			s.State = "fin_wait_1"
		}
	} else if strings.Contains(flagsStr, "RST") {
		// RST indicates connection reset/abort
		s.State = "closed"
	}
}

// GetPacketCount returns the number of packets in the session.
func (s *Session) GetPacketCount() int {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return len(s.Packets)
}

// GetDuration returns the duration of the session in seconds.
func (s *Session) GetDuration() int64 {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	if s.Started == 0 || s.Ended == 0 {
		return 0
	}
	return s.Ended - s.Started
}

// SessionTracker tracks network sessions across multiple packets.
type SessionTracker struct {
	Sessions map[string]*Session // Map of session key string to Session
	Mutex    sync.RWMutex        // Mutex for thread-safe operations
}

// NewSessionTracker creates a new SessionTracker.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		Sessions: make(map[string]*Session),
	}
}

// AddPacket adds a packet to the appropriate session, creating a new session if necessary.
func (t *SessionTracker) AddPacket(packet *Packet) {
	// Extract session key from packet
	key, err := ExtractSessionKey(packet)
	if err != nil {
		// Skip packets that don't have enough information for a session key
		return
	}

	// Normalize the key to ensure consistent session identification
	normalizedKey := key.Normalized()
	keyStr := normalizedKey.String()

	// Add packet to the appropriate session
	t.Mutex.Lock()
	session, exists := t.Sessions[keyStr]
	if !exists {
		// Create a new session
		session = NewSession(normalizedKey)
		t.Sessions[keyStr] = session
	}
	t.Mutex.Unlock()

	// Add packet to the session
	session.AddPacket(packet)
}

// GetSession returns the session with the given key, or nil if not found.
func (t *SessionTracker) GetSession(key SessionKey) *Session {
	normalizedKey := key.Normalized()
	keyStr := normalizedKey.String()

	t.Mutex.RLock()
	defer t.Mutex.RUnlock()

	return t.Sessions[keyStr]
}

// GetAllSessions returns a slice of all sessions.
func (t *SessionTracker) GetAllSessions() []*Session {
	t.Mutex.RLock()
	defer t.Mutex.RUnlock()

	sessions := make([]*Session, 0, len(t.Sessions))
	for _, session := range t.Sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// GetSessionCount returns the number of sessions being tracked.
func (t *SessionTracker) GetSessionCount() int {
	t.Mutex.RLock()
	defer t.Mutex.RUnlock()

	return len(t.Sessions)
}

// ExtractSessionKey extracts a session key from a packet.
func ExtractSessionKey(packet *Packet) (SessionKey, error) {
	// Initialize empty key
	key := SessionKey{}

	// Extract transport protocol
	transportLayer := packet.TransportLayer()
	if transportLayer == "" {
		// If no transport layer, try to use the highest layer as the protocol
		key.Protocol = strings.ToLower(packet.HighestLayer())
	} else {
		key.Protocol = transportLayer
	}

	// Extract IP addresses
	ipLayer := packet.GetLayer("ip")
	if ipLayer == nil {
		// Try IPv6
		ipLayer = packet.GetLayer("ipv6")
	}

	if ipLayer == nil {
		return key, fmt.Errorf("no IP layer found in packet")
	}

	// Extract source and destination IP addresses
	var srcIP, dstIP interface{}
	if ipLayer.Name == "ip" {
		srcIP = ipLayer.GetField("ip.src")
		dstIP = ipLayer.GetField("ip.dst")
	} else {
		// IPv6
		srcIP = ipLayer.GetField("ipv6.src")
		dstIP = ipLayer.GetField("ipv6.dst")
	}

	if srcIP == nil || dstIP == nil {
		return key, fmt.Errorf("missing IP address information")
	}

	key.SrcIP = fmt.Sprintf("%v", srcIP)
	key.DstIP = fmt.Sprintf("%v", dstIP)

	// Extract port information if available
	tcpLayer := packet.GetLayer("tcp")
	udpLayer := packet.GetLayer("udp")

	if tcpLayer != nil {
		// Extract TCP ports
		srcPort := tcpLayer.GetField("tcp.srcport")
		dstPort := tcpLayer.GetField("tcp.dstport")

		if srcPort != nil && dstPort != nil {
			key.SrcPort = fmt.Sprintf("%v", srcPort)
			key.DstPort = fmt.Sprintf("%v", dstPort)
		}
	} else if udpLayer != nil {
		// Extract UDP ports
		srcPort := udpLayer.GetField("udp.srcport")
		dstPort := udpLayer.GetField("udp.dstport")

		if srcPort != nil && dstPort != nil {
			key.SrcPort = fmt.Sprintf("%v", srcPort)
			key.DstPort = fmt.Sprintf("%v", dstPort)
		}
	} else {
		// No port information available, use empty strings
		key.SrcPort = ""
		key.DstPort = ""
	}

	return key, nil
}
