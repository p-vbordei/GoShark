package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"sync"

	"GoShark/goshark/capture"
	"GoShark/goshark/packet"
	"GoShark/goshark/tshark"
)

func main() {
	var stdout io.Reader
	var stderr io.Reader

	version, err := tshark.GetTSharkVersion("")
	if err != nil {
		log.Fatalf("Error getting TShark version: %v", err)
	}
	fmt.Printf("TShark Version: %s\n", version)

	// Live Capture Example (Commented Out for Display Filter Example)
	/*
	// Replace "en0" with your network interface name (e.g., "en0", "wlan0").
	// You might need to run this program with elevated privileges (e.g., sudo) for live capture.
	//
	// Common BPF (Berkeley Packet Filter) Syntax Examples:
	//   - "host 192.168.1.1": Traffic to or from a specific IP address.
	//   - "src host 192.168.1.1": Traffic from a specific source IP address.
	//   - "dst host 192.168.1.1": Traffic to a specific destination IP address.
	//   - "port 80": Traffic to or from a specific port.
	//   - "src port 80": Traffic from a specific source port.
	//   - "dst port 80": Traffic to a specific destination port.
	//   - "tcp": Only TCP traffic.
	//   - "udp": Only UDP traffic.
	//   - "icmp": Only ICMP traffic.
	//   - "tcp port 80 or udp port 53": TCP on port 80 or UDP on port 53.
	//   - "net 192.168.1.0/24": Traffic to or from a specific subnet.
	liveCapture := capture.NewLiveCapture("en0",
		capture.WithPacketCount(5),
		capture.WithCaptureFilter("icmp"),
	)

	// Start the live capture process
	stdout, stderr, err = liveCapture.Start()
	if err != nil {
		log.Fatalf("Failed to start live capture: %v", err)
	}

	fmt.Println("Starting live capture...")
	*/

	// File Capture Example with Display Filter
	//	Common Wireshark Display Filter Syntax Examples:
	//   - "ip.addr == 192.168.1.1": Packets where the IP source or destination is 192.168.1.1.
	//   - "ip.src == 192.168.1.1": Packets from source IP 192.168.1.1.
	//   - "ip.dst == 192.168.1.1": Packets to destination IP 192.168.1.1.
	//   - "tcp.port == 80": TCP packets with source or destination port 80.
	//   - "tcp.srcport == 80": TCP packets from source port 80.
	//   - "tcp.dstport == 80": TCP packets to destination port 80.
	//   - "http": Only HTTP protocol packets.
	//   - "dns": Only DNS protocol packets.
	//   - "tcp.flags.syn == 1 and tcp.flags.ack == 0": TCP SYN packets (start of handshake).
	//   - "frame.len > 100": Packets with a length greater than 100 bytes.
	//   - "not arp": Exclude ARP packets.
	//   - "(ip.addr == 192.168.1.1 and tcp.port == 80) or udp.port == 53": Complex filter using logical operators.
	// Create a new file capture instance
	fileCapture, err := capture.NewFileCapture("non_existent.pcap",
		capture.WithPacketCount(5),
		capture.WithDisplayFilter("ip"),
	)
	if err != nil {
		log.Fatalf("Error creating file capture: %v", err)
	}

	// Start the capture process
	stdout, stderr, err = fileCapture.Start()
	if err != nil {
		log.Fatalf("Failed to start file capture: %v", err)
	}

	fmt.Println("Starting file capture with display filter...")

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
				
				// Parse the packet
				p, err := packet.NewPacketFromJSON(packetBytes)
				if err != nil {
					log.Printf("Error parsing packet JSON: %v", err)
					continue
				}

				// Access packet layers and fields
				fmt.Printf("Packet %s (Length: %s)\n", p.FrameNumber, p.FrameLen)
				fmt.Printf("  Highest Layer: %s\n", p.HighestLayer())
				fmt.Printf("  Transport Layer: %s\n", p.TransportLayer())

				if ethLayer := p.GetLayer("eth"); ethLayer != nil {
					fmt.Printf("  Ethernet Source: %v, Destination: %v\n", ethLayer.Fields["eth.src"], ethLayer.Fields["eth.dst"])
				}
				if ipLayer := p.GetLayer("ip"); ipLayer != nil {
					fmt.Printf("  IP Source: %v, Destination: %v\n", ipLayer.Fields["ip.src"], ipLayer.Fields["ip.dst"])
				}
				if tcpLayer := p.GetLayer("tcp"); tcpLayer != nil {
					fmt.Printf("  TCP Source Port: %v, Destination Port: %v\n", tcpLayer.Fields["tcp.srcport"], tcpLayer.Fields["tcp.dstport"])
				}

				// Example of accessing a specific field from a layer
				if frameLayer := p.GetLayer("frame"); frameLayer != nil {
					if timeField, ok := frameLayer.Fields["frame.time"]; ok {
						fmt.Printf("  Frame Time: %v\n", timeField)
					}
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
	if err := fileCapture.Wait(); err != nil {
		log.Printf("TShark command finished with error: %v", err)
	}

	fmt.Println("File capture finished.")
}
