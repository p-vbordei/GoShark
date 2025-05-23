package packet

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// This file extends the Layer struct defined in packet.go with protocol-specific functionality

// GetString retrieves a field's value as a string.
func (l *Layer) GetString(name string, defaultValue string) string {
	val := l.Get(name, defaultValue)
	switch v := val.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// GetInt retrieves a field's value as an integer.
func (l *Layer) GetInt(name string, defaultValue int) int {
	val := l.Get(name, defaultValue)
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return defaultValue
		}
		return i
	default:
		return defaultValue
	}
}

// GetBool retrieves a field's value as a boolean.
func (l *Layer) GetBool(name string, defaultValue bool) bool {
	val := l.Get(name, defaultValue)
	switch v := val.(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return defaultValue
		}
		return b
	default:
		return defaultValue
	}
}

// Layer-specific helper methods for string conversion and type handling

// ProtocolLayerInterface defines the interface for protocol-specific layers.
type ProtocolLayerInterface interface {
	// GetName returns the name of the protocol layer.
	GetName() string
	
	// GetLayer returns the underlying Layer.
	GetLayer() *Layer
}

// BaseProtocolLayer provides common functionality for all protocol-specific layers.
type BaseProtocolLayer struct {
	Layer *Layer
}

// GetName returns the name of the protocol layer.
func (b *BaseProtocolLayer) GetName() string {
	return b.Layer.Name
}

// GetLayer returns the underlying Layer.
func (b *BaseProtocolLayer) GetLayer() *Layer {
	return b.Layer
}

// HTTPLayer represents an HTTP protocol layer.
type HTTPLayer struct {
	BaseProtocolLayer
}

// NewHTTPLayer creates a new HTTPLayer from a generic Layer.
func NewHTTPLayer(layer *Layer) *HTTPLayer {
	return &HTTPLayer{
		BaseProtocolLayer: BaseProtocolLayer{Layer: layer},
	}
}

// IsRequest returns true if this is an HTTP request.
func (h *HTTPLayer) IsRequest() bool {
	return h.Layer.HasField("http.request")
}

// IsResponse returns true if this is an HTTP response.
func (h *HTTPLayer) IsResponse() bool {
	return h.Layer.HasField("http.response")
}

// GetMethod returns the HTTP method for a request.
func (h *HTTPLayer) GetMethod() string {
	return h.Layer.GetString("http.request.method", "")
}

// GetURI returns the URI for an HTTP request.
func (h *HTTPLayer) GetURI() string {
	return h.Layer.GetString("http.request.uri", "")
}

// GetVersion returns the HTTP version.
func (h *HTTPLayer) GetVersion() string {
	return h.Layer.GetString("http.version", "")
}

// GetStatusCode returns the status code for an HTTP response.
func (h *HTTPLayer) GetStatusCode() int {
	return h.Layer.GetInt("http.response.code", 0)
}

// GetStatusMessage returns the status message for an HTTP response.
func (h *HTTPLayer) GetStatusMessage() string {
	return h.Layer.GetString("http.response.phrase", "")
}

// GetHeaders returns all HTTP headers as a map.
func (h *HTTPLayer) GetHeaders() map[string]string {
	headers := make(map[string]string)
	
	for name, value := range h.Layer.Fields {
		if strings.HasPrefix(name, "http.header.") {
			headerName := strings.TrimPrefix(name, "http.header.")
			headers[headerName] = fmt.Sprintf("%v", value)
		}
	}
	
	return headers
}

// DNSLayer represents a DNS protocol layer.
type DNSLayer struct {
	BaseProtocolLayer
}

// NewDNSLayer creates a new DNSLayer from a generic Layer.
func NewDNSLayer(layer *Layer) *DNSLayer {
	return &DNSLayer{
		BaseProtocolLayer: BaseProtocolLayer{Layer: layer},
	}
}

// IsQuery returns true if this is a DNS query.
func (d *DNSLayer) IsQuery() bool {
	return d.Layer.GetBool("dns.flags.response", false) == false
}

// IsResponse returns true if this is a DNS response.
func (d *DNSLayer) IsResponse() bool {
	return d.Layer.GetBool("dns.flags.response", false) == true
}

// GetQueryName returns the query name for a DNS query.
func (d *DNSLayer) GetQueryName() string {
	return d.Layer.GetString("dns.qry.name", "")
}

// GetQueryType returns the query type for a DNS query.
func (d *DNSLayer) GetQueryType() string {
	return d.Layer.GetString("dns.qry.type", "")
}

// GetResponseCode returns the response code for a DNS response.
func (d *DNSLayer) GetResponseCode() int {
	return d.Layer.GetInt("dns.flags.rcode", 0)
}

// TCPLayer represents a TCP protocol layer.
type TCPLayer struct {
	BaseProtocolLayer
}

// NewTCPLayer creates a new TCPLayer from a generic Layer.
func NewTCPLayer(layer *Layer) *TCPLayer {
	return &TCPLayer{
		BaseProtocolLayer: BaseProtocolLayer{Layer: layer},
	}
}

// GetSourcePort returns the source port.
func (t *TCPLayer) GetSourcePort() int {
	return t.Layer.GetInt("tcp.srcport", 0)
}

// GetDestinationPort returns the destination port.
func (t *TCPLayer) GetDestinationPort() int {
	return t.Layer.GetInt("tcp.dstport", 0)
}

// GetSequenceNumber returns the sequence number.
func (t *TCPLayer) GetSequenceNumber() int {
	return t.Layer.GetInt("tcp.seq", 0)
}

// GetAcknowledgmentNumber returns the acknowledgment number.
func (t *TCPLayer) GetAcknowledgmentNumber() int {
	return t.Layer.GetInt("tcp.ack", 0)
}

// HasSYN returns true if the SYN flag is set.
func (t *TCPLayer) HasSYN() bool {
	return t.Layer.GetBool("tcp.flags.syn", false)
}

// HasACK returns true if the ACK flag is set.
func (t *TCPLayer) HasACK() bool {
	return t.Layer.GetBool("tcp.flags.ack", false)
}

// HasFIN returns true if the FIN flag is set.
func (t *TCPLayer) HasFIN() bool {
	return t.Layer.GetBool("tcp.flags.fin", false)
}

// HasRST returns true if the RST flag is set.
func (t *TCPLayer) HasRST() bool {
	return t.Layer.GetBool("tcp.flags.reset", false)
}

// IPLayer represents an IP protocol layer.
type IPLayer struct {
	BaseProtocolLayer
}

// NewIPLayer creates a new IPLayer from a generic Layer.
func NewIPLayer(layer *Layer) *IPLayer {
	return &IPLayer{
		BaseProtocolLayer: BaseProtocolLayer{Layer: layer},
	}
}

// GetVersion returns the IP version.
func (i *IPLayer) GetVersion() int {
	if i.Layer.Name == "ipv6" {
		return 6
	}
	return 4
}

// GetSourceIP returns the source IP address.
func (i *IPLayer) GetSourceIP() net.IP {
	var ipStr string
	if i.GetVersion() == 4 {
		ipStr = i.Layer.GetString("ip.src", "")
	} else {
		ipStr = i.Layer.GetString("ipv6.src", "")
	}
	return net.ParseIP(ipStr)
}

// GetDestinationIP returns the destination IP address.
func (i *IPLayer) GetDestinationIP() net.IP {
	var ipStr string
	if i.GetVersion() == 4 {
		ipStr = i.Layer.GetString("ip.dst", "")
	} else {
		ipStr = i.Layer.GetString("ipv6.dst", "")
	}
	return net.ParseIP(ipStr)
}

// GetTTL returns the Time To Live value.
func (i *IPLayer) GetTTL() int {
	if i.GetVersion() == 4 {
		return i.Layer.GetInt("ip.ttl", 0)
	}
	return i.Layer.GetInt("ipv6.hlim", 0)
}

// GetProtocol returns the protocol number.
func (i *IPLayer) GetProtocol() int {
	if i.GetVersion() == 4 {
		return i.Layer.GetInt("ip.proto", 0)
	}
	return i.Layer.GetInt("ipv6.nxt", 0)
}

// GetProtocolName returns the protocol name.
func (i *IPLayer) GetProtocolName() string {
	proto := i.GetProtocol()
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown (%d)", proto)
	}
}

// ConvertToHTTPLayer converts a generic Layer to an HTTPLayer if it's an HTTP layer.
func ConvertToHTTPLayer(layer *Layer) *HTTPLayer {
	if layer.Name == "http" {
		return NewHTTPLayer(layer)
	}
	return nil
}

// ConvertToDNSLayer converts a generic Layer to a DNSLayer if it's a DNS layer.
func ConvertToDNSLayer(layer *Layer) *DNSLayer {
	if layer.Name == "dns" {
		return NewDNSLayer(layer)
	}
	return nil
}

// ConvertToTCPLayer converts a generic Layer to a TCPLayer if it's a TCP layer.
func ConvertToTCPLayer(layer *Layer) *TCPLayer {
	if layer.Name == "tcp" {
		return NewTCPLayer(layer)
	}
	return nil
}

// ConvertToIPLayer converts a generic Layer to an IPLayer if it's an IP layer.
func ConvertToIPLayer(layer *Layer) *IPLayer {
	if layer.Name == "ip" || layer.Name == "ipv6" {
		return NewIPLayer(layer)
	}
	return nil
}
