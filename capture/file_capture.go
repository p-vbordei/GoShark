package capture

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"GoShark/packet"
	"GoShark/tshark"
)

// FileCapture represents a packet capture from a file.
type FileCapture struct {
	Capture
	FilePath string
}

// NewFileCapture creates a new FileCapture instance.
func NewFileCapture(filePath string, options ...Option) (*FileCapture, error) {
	c := &FileCapture{
		Capture: Capture{
			UseJSON:     true,
			KeepPackets: true,
		},
		FilePath: filePath,
	}

	for _, option := range options {
		option(c)
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
func (c *FileCapture) Start() (io.ReadCloser, io.ReadCloser, error) {
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

	cmd, err := tshark.RunTSharkCommand(c.TSharkPath, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run tshark command: %w", err)
	}
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

// SniffContinuously sniffs packets from the file capture and streams them on a channel.
func (c *FileCapture) SniffContinuously(ctx context.Context) (<-chan *packet.Packet, error) {
	stdout, stderr, err := c.Start()
	if err != nil {
		return nil, err
	}
	return c.sniffStream(ctx, stdout, stderr)
}

// ApplyOnPackets applies the callback to all captured packets.
func (c *FileCapture) ApplyOnPackets(callback func(*packet.Packet) bool, ctx context.Context) error {
	return c.Capture.ApplyOnPackets(callback, ctx, func() (io.ReadCloser, io.ReadCloser, error) {
		return c.Start()
	})
}

// LoadPackets eagerly reads up to count packets from the file (count <= 0 means
// all) and buffers them for indexed access via Get/Len/Packets.
func (c *FileCapture) LoadPackets(ctx context.Context, count int) ([]*packet.Packet, error) {
	return c.Capture.LoadPackets(ctx, count, c.Start)
}

// ApplyOnPacketsWithLimit applies the callback, stopping after packetCount
// packets or once timeout elapses (see Capture.ApplyOnPacketsWithLimit).
func (c *FileCapture) ApplyOnPacketsWithLimit(callback func(*packet.Packet) bool,
	ctx context.Context, packetCount int, timeout time.Duration) error {
	return c.Capture.ApplyOnPacketsWithLimit(callback, ctx, packetCount, timeout, c.Start)
}
