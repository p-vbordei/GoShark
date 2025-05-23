package capture

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

// FileCapture represents a packet capture from a file.
type FileCapture struct {
	Capture
	FilePath string
}

// NewFileCapture creates a new FileCapture instance.
func NewFileCapture(filePath string, options ...func(*Capture)) (*FileCapture, error) {
	c := &FileCapture{
		Capture:  *NewCapture(options...),
		FilePath: filePath,
	}

	// Check if the file exists and is readable
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("PCAP file not found at %s", filePath)
	} else if err != nil {
		return nil, fmt.Errorf("error accessing PCAP file %s: %w", filePath, err)
	}

	return c, nil
}

// Start begins the file capture process.
func (c *FileCapture) Start() (stdout io.Reader, stderr io.Reader, err error) {
	if c.FilePath == "" {
		return nil, nil, fmt.Errorf("file path cannot be empty for file capture")
	}

	// Start with -r flag and file path
	args := []string{"-r", c.FilePath}

	// Get common tshark arguments from the Capture struct
	tsharkArgs, err := c.getTSharkArgs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tshark arguments: %w", err)
	}

	// Append the common arguments
	args = append(args, tsharkArgs...)

	cmd := exec.Command("tshark", args...)
	c.cmd = cmd

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start tshark command: %w", err)
	}

	// No need to wait here, main.go will call c.Wait()
	return stdoutPipe, stderrPipe, nil
}
