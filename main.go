package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"GoShark/packet"
)

// Helper function to safely get string fields
func getStringField(fields map[string]interface{}, key string) string {
	if val, ok := fields[key].(string); ok {
		return val
	}
	return ""
}

func main() {
	// Verify TShark is available
	if _, err := exec.LookPath("tshark"); err != nil {
		log.Fatal("TShark not found in PATH:", err)
	}

	// Get input file path
	inputFile := os.Getenv("PCAP_FILE")
	if inputFile == "" {
		inputFile = "/data-input/profinet.pcap"
	}

	// Verify PCAP file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		log.Fatalf("PCAP file not found at %s", inputFile)
	}

	// Create output directory
	outputDir := "/data-output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}
	outputFile := filepath.Join(outputDir, "profinet_analysis.txt")

	// Start TShark with Profinet IO decoding
	cmd := exec.Command("tshark",
		"-r", inputFile,
		"-d", "udp.port==34964,pn_io",
		"-T", "json",
		"-Y", "pn_io",
		"-V")

	// Create pipes before starting the process
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start TShark: %v", err)
	}

	// Process stderr in a goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("TShark stderr: %s", scanner.Text())
		}
	}()

	// Process output
	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	// Process stdout in main goroutine
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("Processing packet: %s", line)
		
		p, err := packet.NewPacketFromJSON([]byte(line))
		if err != nil {
			log.Printf("Error parsing packet: %v", err)
			continue
		}

		fmt.Fprintf(outFile, "Packet %s\n", p.FrameNumber)
		
		// Check for Profinet IO layer
		if pn_io := p.GetLayer("pn_io"); pn_io != nil {
			fmt.Fprintf(outFile, "PROFINET IO Packet %s\n", p.FrameNumber)
			fmt.Fprintf(outFile, "  Frame Time: %s\n", p.FrameTime)
			
			// Process IO-specific fields
			if op := getStringField(pn_io.Fields, "pn_io.operation"); op != "" {
				fmt.Fprintf(outFile, "  Operation: %s\n", op)
			}
			if api := getStringField(pn_io.Fields, "pn_io.api"); api != "" {
				fmt.Fprintf(outFile, "  API: %s\n", api)
			}
			if slot := getStringField(pn_io.Fields, "pn_io.slot"); slot != "" {
				fmt.Fprintf(outFile, "  Slot: %s\n", slot)
			}
			if subslot := getStringField(pn_io.Fields, "pn_io.subslot"); subslot != "" {
				fmt.Fprintf(outFile, "  Subslot: %s\n", subslot)
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("TShark finished with error: %v", err)
	}

	fmt.Println("Analysis complete. Output written to:", outputFile)
}