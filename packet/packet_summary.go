package packet

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PacketSummary provides a condensed view of packet information
type PacketSummary struct {
	Number      int
	Time        time.Time
	SourceIP    string
	DestIP      string
	Protocol    string
	Length      int
	Info        string
	Description string
}

// NewPacketSummary creates a new packet summary from a packet
func NewPacketSummary(packet *Packet) (*PacketSummary, error) {
	summary := &PacketSummary{}

	// Extract frame number
	if packet.FrameNumber != "" {
		num, err := strconv.Atoi(packet.FrameNumber)
		if err == nil {
			summary.Number = num
		}
	}

	// Extract time
	sniffTime, err := packet.SniffTime()
	if err == nil {
		summary.Time = sniffTime
	}

	// Extract length
	if packet.FrameLen != "" {
		length, err := strconv.Atoi(packet.FrameLen)
		if err == nil {
			summary.Length = length
		}
	}

	// Extract protocol (highest layer)
	summary.Protocol = packet.HighestLayer()

	// Extract IP addresses
	ipLayer := packet.GetLayer("ip")
	if ipLayer == nil {
		ipLayer = packet.GetLayer("ipv6")
	}

	if ipLayer != nil {
		// Try to get source and destination IP addresses
		if srcIP := ipLayer.GetField("src"); srcIP != nil {
			summary.SourceIP = fmt.Sprintf("%v", srcIP)
		}

		if dstIP := ipLayer.GetField("dst"); dstIP != nil {
			summary.DestIP = fmt.Sprintf("%v", dstIP)
		}
	}

	// Extract info based on protocol
	summary.Info = extractInfoFromPacket(packet, summary.Protocol)

	// Create a description
	summary.Description = fmt.Sprintf("%s %s → %s %s", 
		summary.Protocol, 
		summary.SourceIP, 
		summary.DestIP, 
		summary.Info)

	return summary, nil
}

// String returns a string representation of the packet summary
func (s *PacketSummary) String() string {
	return fmt.Sprintf("#%d %s %s → %s [%s] %d bytes: %s",
		s.Number,
		s.Time.Format("15:04:05.000000"),
		s.SourceIP,
		s.DestIP,
		s.Protocol,
		s.Length,
		s.Info)
}

// extractInfoFromPacket extracts protocol-specific information from a packet
func extractInfoFromPacket(packet *Packet, protocol string) string {
	switch strings.ToLower(protocol) {
	case "http":
		return extractHTTPInfo(packet)
	case "dns":
		return extractDNSInfo(packet)
	case "tcp":
		return extractTCPInfo(packet)
	case "udp":
		return extractUDPInfo(packet)
	case "icmp":
		return extractICMPInfo(packet)
	default:
		return ""
	}
}

// extractHTTPInfo extracts HTTP-specific information
func extractHTTPInfo(packet *Packet) string {
	httpLayer := packet.GetLayer("http")
	if httpLayer == nil {
		return ""
	}

	// Check if it's a request or response
	if method := httpLayer.GetField("request_method"); method != nil {
		// It's a request
		uri := httpLayer.GetField("request_uri")
		if uri != nil {
			return fmt.Sprintf("%v %v", method, uri)
		}
		return fmt.Sprintf("%v", method)
	}

	// Check if it's a response
	if statusCode := httpLayer.GetField("response_code"); statusCode != nil {
		// It's a response
		statusPhrase := httpLayer.GetField("response_phrase")
		if statusPhrase != nil {
			return fmt.Sprintf("%v %v", statusCode, statusPhrase)
		}
		return fmt.Sprintf("%v", statusCode)
	}

	return ""
}

// extractDNSInfo extracts DNS-specific information
func extractDNSInfo(packet *Packet) string {
	dnsLayer := packet.GetLayer("dns")
	if dnsLayer == nil {
		return ""
	}

	// Check if it's a query
	if queryName := dnsLayer.GetField("qry_name"); queryName != nil {
		// It's a query
		queryType := dnsLayer.GetField("qry_type")
		if queryType != nil {
			return fmt.Sprintf("Query: %v (%v)", queryName, queryType)
		}
		return fmt.Sprintf("Query: %v", queryName)
	}

	// Check if it's a response
	if respName := dnsLayer.GetField("resp_name"); respName != nil {
		// It's a response
		respType := dnsLayer.GetField("resp_type")
		respData := dnsLayer.GetField("resp_data")
		if respType != nil && respData != nil {
			return fmt.Sprintf("Response: %v (%v) = %v", respName, respType, respData)
		}
		return fmt.Sprintf("Response: %v", respName)
	}

	return ""
}

// extractTCPInfo extracts TCP-specific information
func extractTCPInfo(packet *Packet) string {
	tcpLayer := packet.GetLayer("tcp")
	if tcpLayer == nil {
		return ""
	}

	// Get source and destination ports
	srcPort := tcpLayer.GetField("srcport")
	dstPort := tcpLayer.GetField("dstport")
	if srcPort != nil && dstPort != nil {
		return fmt.Sprintf("Port %v → %v", srcPort, dstPort)
	}

	return ""
}

// extractUDPInfo extracts UDP-specific information
func extractUDPInfo(packet *Packet) string {
	udpLayer := packet.GetLayer("udp")
	if udpLayer == nil {
		return ""
	}

	// Get source and destination ports
	srcPort := udpLayer.GetField("srcport")
	dstPort := udpLayer.GetField("dstport")
	if srcPort != nil && dstPort != nil {
		return fmt.Sprintf("Port %v → %v", srcPort, dstPort)
	}

	return ""
}

// extractICMPInfo extracts ICMP-specific information
func extractICMPInfo(packet *Packet) string {
	icmpLayer := packet.GetLayer("icmp")
	if icmpLayer == nil {
		return ""
	}

	// Get ICMP type and code
	icmpType := icmpLayer.GetField("type")
	icmpCode := icmpLayer.GetField("code")
	if icmpType != nil {
		if icmpCode != nil {
			return fmt.Sprintf("Type: %v, Code: %v", icmpType, icmpCode)
		}
		return fmt.Sprintf("Type: %v", icmpType)
	}

	return ""
}
