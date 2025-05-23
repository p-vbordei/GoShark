package consts

// TransportLayers defines the list of transport layer protocols
var TransportLayers = []string{"TCP", "UDP", "SCTP", "DCCP"}

// NetworkLayers defines the list of network layer protocols
var NetworkLayers = []string{"IP", "IPv4", "IPv6", "ICMP", "ICMPv6"}

// LinkLayers defines the list of link layer protocols
var LinkLayers = []string{"ETH", "ETHERNET", "IEEE802_11"}

// ApplicationLayers defines the list of common application layer protocols
var ApplicationLayers = []string{
	"HTTP",
	"HTTP2",
	"DNS",
	"DHCP",
	"BOOTP",
	"FTP",
	"SMTP",
	"POP",
	"IMAP",
	"SSH",
	"TELNET",
	"TLS",
	"SSL",
	"RTP",
	"SIP",
	"QUIC",
}

// ProtocolHierarchy defines the hierarchy of protocol layers
var ProtocolHierarchy = map[string]int{
	"FRAME":   0,
	"ETH":     10,
	"IP":      20,
	"IPv4":    20,
	"IPv6":    20,
	"ICMP":    25,
	"ICMPv6":  25,
	"TCP":     30,
	"UDP":     30,
	"SCTP":    30,
	"DCCP":    30,
	"HTTP":    40,
	"HTTP2":   40,
	"DNS":     40,
	"DHCP":    40,
	"BOOTP":   40,
	"FTP":     40,
	"SMTP":    40,
	"POP":     40,
	"IMAP":    40,
	"SSH":     40,
	"TELNET":  40,
	"TLS":     40,
	"SSL":     40,
	"RTP":     40,
	"SIP":     40,
	"QUIC":    40,
}

// IsTransportLayer checks if a protocol is a transport layer protocol
func IsTransportLayer(protocol string) bool {
	for _, p := range TransportLayers {
		if p == protocol {
			return true
		}
	}
	return false
}

// IsNetworkLayer checks if a protocol is a network layer protocol
func IsNetworkLayer(protocol string) bool {
	for _, p := range NetworkLayers {
		if p == protocol {
			return true
		}
	}
	return false
}

// IsLinkLayer checks if a protocol is a link layer protocol
func IsLinkLayer(protocol string) bool {
	for _, p := range LinkLayers {
		if p == protocol {
			return true
		}
	}
	return false
}

// IsApplicationLayer checks if a protocol is an application layer protocol
func IsApplicationLayer(protocol string) bool {
	for _, p := range ApplicationLayers {
		if p == protocol {
			return true
		}
	}
	return false
}

// GetProtocolLayer returns the layer number of a protocol
func GetProtocolLayer(protocol string) int {
	if layer, ok := ProtocolHierarchy[protocol]; ok {
		return layer
	}
	return -1
}
