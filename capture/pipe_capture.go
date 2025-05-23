package capture

import (
	"fmt"
	"io"
	"os/exec"
)

// PipeCapture represents a capture that reads packets from a pipe or reader.
type PipeCapture struct {
	*Capture
	pipe io.Reader
}

// NewPipeCapture creates a new PipeCapture instance that reads from the given pipe.
func NewPipeCapture(pipe io.Reader, options ...func(*Capture)) *PipeCapture {
	c := NewCapture(options...)

	return &PipeCapture{
		Capture: c,
		pipe:    pipe,
	}
}

// Start begins the pipe capture process.
func (pc *PipeCapture) Start() (stdout io.ReadCloser, stderr io.ReadCloser, err error) {
	// Get tshark arguments
	tsharkArgs, err := pc.getTSharkArgs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tshark arguments: %w", err)
	}

	// Add -r - to read from stdin
	tsharkArgs = append(tsharkArgs, "-r", "-")

	// Get tshark path
	tsharkPath, err := pc.getTSharkPath()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tshark path: %w", err)
	}

	// Create tshark command
	cmd := exec.Command(tsharkPath, tsharkArgs...)

	// Set stdin to the pipe
	cmd.Stdin = pc.pipe

	// Get stdout and stderr pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start tshark command: %w", err)
	}

	// Store the command
	pc.cmd = cmd

	return stdoutPipe, stderrPipe, nil
}

// getTSharkPath returns the path to the tshark executable.
func (pc *PipeCapture) getTSharkPath() (string, error) {
	if pc.TSharkPath != "" {
		return pc.TSharkPath, nil
	}

	// Find tshark in PATH
	path, err := exec.LookPath("tshark")
	if err != nil {
		return "", fmt.Errorf("tshark not found in PATH: %w", err)
	}

	return path, nil
}

// Close closes the pipe if it implements io.Closer.
func (pc *PipeCapture) Close() error {
	// Stop the tshark process if it's running
	if pc.cmd != nil && pc.cmd.Process != nil {
		pc.cmd.Process.Kill()
	}

	// Close the pipe if it's a closer
	if closer, ok := pc.pipe.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}
