package capture

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCaptureOptions(t *testing.T) {
	// Test default options
	cap := NewCapture()
	assert.Equal(t, "", cap.OutputFile, "Default output file should be empty")
	assert.Equal(t, "", cap.DisplayFilter, "Default display filter should be empty")
	assert.Equal(t, "", cap.CaptureFilter, "Default capture filter should be empty")
	assert.True(t, cap.UseJSON, "Default UseJSON should be true")

	// Test with options
	cap = NewCapture(
		WithOutputFile("test.pcap"),
		WithDisplayFilter("tcp"),
	)

	assert.Equal(t, "test.pcap", cap.OutputFile, "Output file should be set")
	assert.Equal(t, "tcp", cap.DisplayFilter, "Display filter should be set")
}

func TestCaptureTSharkArgs(t *testing.T) {
	// Create a capture with options
	cap := NewCapture(
		WithOutputFile("test.pcap"),
		WithDisplayFilter("tcp"),
		WithTSharkPath("/usr/bin/tshark"),
	)

	args, err := cap.getTSharkArgs()
	assert.NoError(t, err)

	// Check that arguments include the expected options
	found := false
	for i, arg := range args {
		if arg == "-w" && i+1 < len(args) && args[i+1] == "test.pcap" {
			found = true
			break
		}
	}
	assert.True(t, found, "Arguments should include output file option")

	found = false
	for i, arg := range args {
		if arg == "-Y" && i+1 < len(args) && args[i+1] == "tcp" {
			found = true
			break
		}
	}
	assert.True(t, found, "Arguments should include display filter option")
}
