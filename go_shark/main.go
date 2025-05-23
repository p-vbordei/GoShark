package main

import (
	"fmt"
	"log"
	"GoShark/tshark"
	"GoShark/capture"
)

func main() {
	version, err := tshark.GetTSharkVersion("")
	if err != nil {
		log.Fatalf("Error getting TShark version: %v", err)
	}
	fmt.Printf("TShark Version: %s\n", version)

	// Create a new live capture instance
	liveCapture := capture.NewLiveCapture("lo0") // Use your network interface here, e.g., "eth0", "en0", "lo0"

	// Start the capture
	packetChan, errorChan, err := liveCapture.StartCapture()
	if err != nil {
		log.Fatalf("Error starting live capture: %v", err)
	}

	fmt.Println("Starting live capture (capturing for 10 seconds)...")

	// Process captured packets
	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				packetChan = nil // Channel closed
				break
			}
			fmt.Printf("Captured Packet: %s\n", string(packet))
		case err, ok := <-errorChan:
			if !ok {
				errorChan = nil // Channel closed
				break
			}
			log.Printf("Capture Error: %v", err)
		}

		if packetChan == nil && errorChan == nil {
			break // Both channels closed
		}
	}

	fmt.Println("Live capture finished.")
}
