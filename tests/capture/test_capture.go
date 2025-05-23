package capture_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"GoShark/capture"
	"GoShark/tests"
)

func TestCaptureOptions(t *testing.T) {
	// Test default options
	cap := capture.NewCapture()
	assert.Equal(t, "", cap.OutputFile, "Default output file should be empty")
	assert.Equal(t, "", cap.DisplayFilter, "Default display filter should be empty")
	assert.Equal(t, "", cap.CaptureFilter, "Default capture filter should be empty")
	assert.True(t, cap.UseJSON, "Default UseJSON should be true")

	// Test with options
	cap = capture.NewCapture(
		capture.WithOutputFile("test.pcap"),
		capture.WithDisplayFilter("tcp"),
	)

	assert.Equal(t, "test.pcap", cap.OutputFile, "Output file should be set")
	assert.Equal(t, "tcp", cap.DisplayFilter, "Display filter should be set")
}

func TestCaptureTSharkArgs(t *testing.T) {
	// Create a capture with options
	cap := capture.NewCapture(
		capture.WithOutputFile("test.pcap"),
		capture.WithDisplayFilter("tcp"),
		capture.WithTSharkPath("/usr/bin/tshark"),
	)

	// Test getTSharkArgs (we need to access it through reflection since it's private)
	r := reflect.ValueOf(cap)
	m := r.MethodByName("getTSharkArgs")
	if !m.IsValid() {
		t.Skip("getTSharkArgs method not found, skipping test")
	}

	results := m.Call([]reflect.Value{})
	if len(results) != 2 {
		t.Fatal("Expected 2 return values from getTSharkArgs")
	}

	args := results[0].Interface().([]string)
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

func TestCaptureUsesTests(t *testing.T) {
	// This test is just to make sure we're using the tests package
	path := tests.TestDataPath()
	assert.NotEmpty(t, path, "TestDataPath should return a non-empty path")
}
