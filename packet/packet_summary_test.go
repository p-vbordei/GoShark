package packet

import (
	"testing"
	"time"
)

func TestPacketSummary(t *testing.T) {
	// 1. Test basic parsing and HTTP request summary
	pHttpReq := &Packet{
		FrameNumber:    "1",
		FrameLen:       "150",
		FrameTimeEpoch: "1620000000.123456",
		Layers: []Layer{
			{
				Name: "frame",
				Fields: map[string]interface{}{
					"frame.number": "1",
					"frame.len":    "150",
				},
			},
			{
				Name: "ip",
				Fields: map[string]interface{}{
					"src": "192.168.1.10",
					"dst": "192.168.1.20",
				},
			},
			{
				Name: "http",
				Fields: map[string]interface{}{
					"request_method": "GET",
					"request_uri":    "/index.html",
				},
			},
		},
	}

	sum1, err := NewPacketSummary(pHttpReq)
	if err != nil {
		t.Fatalf("Failed to create HTTP request summary: %v", err)
	}

	if sum1.Number != 1 {
		t.Errorf("Expected Number 1, got %d", sum1.Number)
	}
	if sum1.Length != 150 {
		t.Errorf("Expected Length 150, got %d", sum1.Length)
	}
	if sum1.SourceIP != "192.168.1.10" {
		t.Errorf("Expected SourceIP 192.168.1.10, got %s", sum1.SourceIP)
	}
	if sum1.DestIP != "192.168.1.20" {
		t.Errorf("Expected DestIP 192.168.1.20, got %s", sum1.DestIP)
	}
	if sum1.Protocol != "http" {
		t.Errorf("Expected Protocol http, got %s", sum1.Protocol)
	}
	if sum1.Info != "GET /index.html" {
		t.Errorf("Expected Info 'GET /index.html', got '%s'", sum1.Info)
	}

	// 2. Test HTTP response summary
	pHttpResp := &Packet{
		FrameNumber:    "2",
		FrameLen:       "200",
		FrameTimeEpoch: "1620000001.000000",
		Layers: []Layer{
			{
				Name: "ip",
				Fields: map[string]interface{}{
					"src": "192.168.1.20",
					"dst": "192.168.1.10",
				},
			},
			{
				Name: "http",
				Fields: map[string]interface{}{
					"response_code":   "200",
					"response_phrase": "OK",
				},
			},
		},
	}
	sum2, _ := NewPacketSummary(pHttpResp)
	if sum2.Info != "200 OK" {
		t.Errorf("Expected HTTP response info '200 OK', got '%s'", sum2.Info)
	}

	// Test HTTP response summary without status phrase
	pHttpRespNoPhrase := &Packet{
		Layers: []Layer{
			{
				Name: "http",
				Fields: map[string]interface{}{
					"response_code": "404",
				},
			},
		},
	}
	sumHttpNoPhrase, _ := NewPacketSummary(pHttpRespNoPhrase)
	if sumHttpNoPhrase.Info != "404" {
		t.Errorf("Expected HTTP response info '404', got '%s'", sumHttpNoPhrase.Info)
	}

	// 3. Test DNS query summary
	pDnsQuery := &Packet{
		Layers: []Layer{
			{
				Name: "dns",
				Fields: map[string]interface{}{
					"qry_name": "example.com",
					"qry_type": "A",
				},
			},
		},
	}
	sumDnsQ, _ := NewPacketSummary(pDnsQuery)
	if sumDnsQ.Info != "Query: example.com (A)" {
		t.Errorf("Expected DNS query info 'Query: example.com (A)', got '%s'", sumDnsQ.Info)
	}

	// DNS Query without type
	pDnsQueryNoType := &Packet{
		Layers: []Layer{
			{
				Name: "dns",
				Fields: map[string]interface{}{
					"qry_name": "example.com",
				},
			},
		},
	}
	sumDnsQNoType, _ := NewPacketSummary(pDnsQueryNoType)
	if sumDnsQNoType.Info != "Query: example.com" {
		t.Errorf("Expected DNS query info 'Query: example.com', got '%s'", sumDnsQNoType.Info)
	}

	// 4. Test DNS response summary
	pDnsResp := &Packet{
		Layers: []Layer{
			{
				Name: "dns",
				Fields: map[string]interface{}{
					"resp_name": "example.com",
					"resp_type": "A",
					"resp_data": "93.184.216.34",
				},
			},
		},
	}
	sumDnsR, _ := NewPacketSummary(pDnsResp)
	if sumDnsR.Info != "Response: example.com (A) = 93.184.216.34" {
		t.Errorf("Expected DNS response info 'Response: example.com (A) = 93.184.216.34', got '%s'", sumDnsR.Info)
	}

	// DNS response without type/data
	pDnsRespNoData := &Packet{
		Layers: []Layer{
			{
				Name: "dns",
				Fields: map[string]interface{}{
					"resp_name": "example.com",
				},
			},
		},
	}
	sumDnsRNoData, _ := NewPacketSummary(pDnsRespNoData)
	if sumDnsRNoData.Info != "Response: example.com" {
		t.Errorf("Expected DNS response info 'Response: example.com', got '%s'", sumDnsRNoData.Info)
	}

	// 5. Test TCP summary
	pTcp := &Packet{
		Layers: []Layer{
			{
				Name: "tcp",
				Fields: map[string]interface{}{
					"srcport": "443",
					"dstport": "12345",
				},
			},
		},
	}
	sumTcp, _ := NewPacketSummary(pTcp)
	if sumTcp.Info != "Port 443 → 12345" {
		t.Errorf("Expected TCP info 'Port 443 → 12345', got '%s'", sumTcp.Info)
	}

	// 6. Test UDP summary
	pUdp := &Packet{
		Layers: []Layer{
			{
				Name: "udp",
				Fields: map[string]interface{}{
					"srcport": "53",
					"dstport": "56789",
				},
			},
		},
	}
	sumUdp, _ := NewPacketSummary(pUdp)
	if sumUdp.Info != "Port 53 → 56789" {
		t.Errorf("Expected UDP info 'Port 53 → 56789', got '%s'", sumUdp.Info)
	}

	// 7. Test ICMP summary
	pIcmp := &Packet{
		Layers: []Layer{
			{
				Name: "icmp",
				Fields: map[string]interface{}{
					"type": "8",
					"code": "0",
				},
			},
		},
	}
	sumIcmp, _ := NewPacketSummary(pIcmp)
	if sumIcmp.Info != "Type: 8, Code: 0" {
		t.Errorf("Expected ICMP info 'Type: 8, Code: 0', got '%s'", sumIcmp.Info)
	}

	// ICMP without code
	pIcmpNoCode := &Packet{
		Layers: []Layer{
			{
				Name: "icmp",
				Fields: map[string]interface{}{
					"type": "8",
				},
			},
		},
	}
	sumIcmpNoCode, _ := NewPacketSummary(pIcmpNoCode)
	if sumIcmpNoCode.Info != "Type: 8" {
		t.Errorf("Expected ICMP info 'Type: 8', got '%s'", sumIcmpNoCode.Info)
	}

	// 8. Test String representation
	expectedStr := "#1 18:40:00.123456 192.168.1.10 → 192.168.1.20 [http] 150 bytes: GET /index.html"
	// Set explicit time for comparison
	sum1.Time = time.Date(2021, 5, 3, 18, 40, 0, 123456000, time.UTC)
	if sum1.String() != expectedStr {
		t.Errorf("Expected String() '%s', got '%s'", expectedStr, sum1.String())
	}
}
