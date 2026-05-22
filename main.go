package main

import (
	"context"
	"fmt"
	"log"

	"github.com/p-vbordei/GoShark/capture"
	"github.com/p-vbordei/GoShark/packet"
	"github.com/p-vbordei/GoShark/tshark"
)

// GoShark demo: read the bundled test.pcap and print a summary of each packet.
//
// For a live capture, swap NewFileCapture for:
//
//	capture.NewLiveCapture([]string{"en0"}, capture.WithBPFFilter("tcp"))
//
// which requires elevated privileges (e.g. running with sudo).
func main() {
	version, err := tshark.GetTSharkVersion("")
	if err != nil {
		log.Fatalf("Error getting TShark version: %v", err)
	}
	fmt.Printf("TShark Version: %s\n", version)

	fileCapture, err := capture.NewFileCapture("test.pcap",
		capture.WithDisplayFilter("tcp"),
	)
	if err != nil {
		log.Fatalf("Error creating file capture: %v", err)
	}

	fmt.Println("Reading test.pcap (display filter: tcp) ...")

	count := 0
	err = fileCapture.ApplyOnPackets(func(p *packet.Packet) bool {
		count++
		sniffTime, _ := p.SniffTime()
		fmt.Printf("Packet %s | len=%s | highest=%s | transport=%s | %s\n",
			p.FrameNumber, p.FrameLen, p.HighestLayer(), p.TransportLayer(), sniffTime)

		if ip := p.Layer("ip"); ip != nil {
			fmt.Printf("  IP  %v -> %v\n", ip.Field("src"), ip.Field("dst"))
		}
		if tcp := p.Layer("tcp"); tcp != nil {
			fmt.Printf("  TCP %v -> %v\n", tcp.Field("srcport"), tcp.Field("dstport"))
		}
		return false
	}, context.Background())
	if err != nil {
		log.Fatalf("File capture failed: %v", err)
	}

	fmt.Printf("Done — %d packet(s).\n", count)
}
