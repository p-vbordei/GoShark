package capture

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"GoShark/tshark"
)

// LiveCapture represents a live packet capture session.
type LiveCapture struct {
	TSharkPath string
	Interface  string
	DisplayFilter string
	Permissive bool
	UseJson bool
	CaptureFilter string
	OnlySummary bool
	DisableCap bool
	Decodes []string
	EncryptionKeys []string
	OverridePreference []string
	// Add other fields as needed based on pyshark's Capture class
}

// NewLiveCapture creates a new LiveCapture instance.
func NewLiveCapture(iface string) *LiveCapture {
	return &LiveCapture{
		Interface: iface,
		UseJson: true, // Default to JSON output for easier parsing
	}
}

// StartCapture starts the live packet capture.
func (lc *LiveCapture) StartCapture() (<-chan []byte, <-chan error, error) {
	// Find tshark path
	tsharkPath, err := tshark.GetProcessPath(lc.TSharkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find tshark executable: %w", err)
	}

	// Build tshark command arguments
	args := []string{"--autostop", "duration:10"} // Example: capture for 10 seconds
	if lc.Interface != "" {
		args = append(args, "-i", lc.Interface)
	}

	// Output in JSON format
	if lc.UseJson {
		args = append(args, "-Tjson")
	}

	// Add display filter
	if lc.DisplayFilter != "" {
		// Determine correct flag based on tshark version
		// For now, assume a recent version that supports -Y
		args = append(args, "-Y", lc.DisplayFilter)
	}

	// Add capture filter
	if lc.CaptureFilter != "" {
		args = append(args, "-f", lc.CaptureFilter)
	}

	// Add decodes
	for _, decode := range lc.Decodes {
		args = append(args, "-d", decode)
	}

	// Add encryption keys
	for _, key := range lc.EncryptionKeys {
		args = append(args, "-o", "wlan.enable_decryption:TRUE", "-o", "wlan.wep_keys:"+key)
	}

	// Add override preferences
	for _, pref := range lc.OverridePreference {
		args = append(args, "-o", pref)
	}

	cmd := exec.Command(tsharkPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start tshark command: %w", err)
	}

	packetChan := make(chan []byte)
	errorChan := make(chan error, 1) // Buffered to prevent deadlock on error

	go func() {
		defer close(packetChan)
		defer close(errorChan)

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			packetChan <- scanner.Bytes()
		}
		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading stdout: %w", err)
		}

		// Read stderr to capture any errors from tshark
		errBuf, _ := io.ReadAll(stderr)
		if len(errBuf) > 0 {
			errorChan <- fmt.Errorf("tshark stderr: %s", string(errBuf))
		}

		if err := cmd.Wait(); err != nil {
			errorChan <- fmt.Errorf("tshark command finished with error: %w", err)
		}
	}()

	return packetChan, errorChan, nil
}
