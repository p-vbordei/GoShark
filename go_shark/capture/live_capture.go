package capture

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"GoShark/tshark"
)

// Capture represents a packet capture session.
type Capture struct {
	TSharkPath string
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

// NewCapture creates a new Capture instance.
func NewCapture(options ...func(*Capture)) *Capture {
	c := &Capture{
		UseJson: true, // Default to JSON output for easier parsing
	}
	for _, option := range options {
		option(c)
	}
	return c
}

// LiveCapture represents a live packet capture from a network interface.
type LiveCapture struct {
	*Capture
	Interface   string
	MonitorMode bool
	// Add other live capture specific fields like bpf_filter, etc.
	cmd *exec.Cmd
}

// NewLiveCapture creates a new LiveCapture object.
func NewLiveCapture(iface string, options ...func(*Capture)) *LiveCapture {
	c := NewCapture(options...)
	return &LiveCapture{
		Capture:   c,
		Interface: iface,
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

// Start starts the live capture process.
// It returns readers for stdout and stderr.
func (lc *LiveCapture) Start() (io.ReadCloser, io.ReadCloser, error) {
	args, err := lc.Capture.getTSharkArgs()
	if err != nil {
		return nil, nil, err
	}

	// Add live capture specific arguments
	args = append(args, "-i", lc.Interface)
	if lc.MonitorMode {
		args = append(args, "-I")
	}

	cmd, err := tshark.RunTSharkCommand(lc.TSharkPath, args...)
	if err != nil {
		return nil, nil, err
	}
	lc.cmd = cmd

	return cmd.Stdout, cmd.Stderr, nil
}

func (c *Capture) getTSharkArgs() ([]string, error) {
	// Build tshark command arguments
	args := []string{}
	// Add display filter
	if c.DisplayFilter != "" {
		// Determine correct flag based on tshark version
		// For now, assume a recent version that supports -Y
		args = append(args, "-Y", c.DisplayFilter)
	}

	// Add capture filter
	if c.CaptureFilter != "" {
		args = append(args, "-f", c.CaptureFilter)
	}

	// Add decodes
	for _, decode := range c.Decodes {
		args = append(args, "-d", decode)
	}

	// Add encryption keys
	for _, key := range c.EncryptionKeys {
		args = append(args, "-o", "wlan.enable_decryption:TRUE", "-o", "wlan.wep_keys:"+key)
	}

	// Add override preferences
	for _, pref := range c.OverridePreference {
		args = append(args, "-o", pref)
	}

	return args, nil
}
