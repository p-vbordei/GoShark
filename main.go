package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"sync"

	"GoShark/capture"
	"GoShark/packet"
	"GoShark/tshark"
)

func main() {
	version, err := tshark.GetTSharkVersion("")
	if err != nil {
		log.Fatalf("Error getting TShark version: %v", err)
	}
	fmt.Printf("TShark Version: %s\n", version)

	// Create a new live capture instance
	liveCapture := capture.NewLiveCapture("lo0", capture.WithPacketCount(10)) // Use your network interface here, e.g., "eth0", "en0", "lo0"

	// Start the capture process
	stdout, stderr, err := liveCapture.Start()
	if err != nil {
		log.Fatalf("Error starting live capture: %v", err)
	}

	fmt.Println("Starting live capture...")

	packetChan := make(chan []byte)
	errorChan := make(chan error, 1) // Buffered to prevent deadlock on error

	var wg sync.WaitGroup
	wg.Add(3) // Three goroutines: stdout reader, stderr reader, and packet processor

	// Goroutine to read from stdout (packets)
	go func() {
		defer wg.Done()
		defer close(packetChan)
		
		// Read all output from stdout
		output, err := io.ReadAll(stdout)
		if err != nil {
			errorChan <- fmt.Errorf("error reading stdout: %w", err)
			return // Exit goroutine on error
		}
		packetChan <- output // Send the entire output to the processing goroutine
	}()

	// Goroutine to read from stderr (errors/logs)
	go func() {
		defer wg.Done()
		defer close(errorChan)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			errorChan <- fmt.Errorf("tshark stderr: %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading stderr: %w", err)
		}
	}()

	// Process captured packets and errors
	go func() {
		defer wg.Done()
		for {
			select {
			case packetBytes, ok := <-packetChan:
				if !ok {
					packetChan = nil // Channel closed
					break
				}
				
				// Parse all packets from the collected JSON output
				parsedPackets, err := packet.ParsePackets(packetBytes)
				if err != nil {
					log.Printf("Error parsing packets: %v", err)
					continue
				}

				for _, parsedPacket := range parsedPackets {
					fmt.Println("--- Captured Packet ---")
					// Print some basic info from the parsed packet
					if parsedPacket.Source.Layers != nil {
						fmt.Println("Layers:")
						for layerName := range parsedPacket.Source.Layers {
							fmt.Printf("  - %s\n", layerName)
						}
					}
					fmt.Println("-------------------------")
				}

			case err, ok := <-errorChan:
				if !ok {
					errorChan = nil // Channel closed
					break
				}
				log.Printf("Capture Error: %v", err)
			}

			if packetChan == nil && errorChan == nil {
				return // Both channels closed
			}
		}
	}()

	// Wait for the tshark process to finish and for all goroutines to complete
	wg.Wait()

	// Ensure the tshark command has finished
	if err := liveCapture.Wait(); err != nil {
		log.Printf("TShark command finished with error: %v", err)
	}

	fmt.Println("Live capture finished.")
}
