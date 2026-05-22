package tshark

import (
	"regexp"
	"testing"
)

func TestGetTSharkPath(t *testing.T) {
	// This test will be skipped if tshark is not installed
	path, err := GetTSharkPath("")
	if err != nil {
		t.Skipf("Skipping test because tshark is not installed: %v", err)
	}

	if path == "" {
		t.Error("TShark path should not be empty")
	}

	// Test with a provided path
	providedPath := "/usr/bin/tshark"
	path, err = GetTSharkPath(providedPath)
	if err != nil {
		t.Errorf("Failed to get tshark path with provided path: %v", err)
	}

	if path != providedPath {
		t.Errorf("Expected path %s, got %s", providedPath, path)
	}
}

func TestRunTSharkCommand(t *testing.T) {
	// This test will be skipped if tshark is not installed
	path, err := GetTSharkPath("")
	if err != nil {
		t.Skipf("Skipping test because tshark is not installed: %v", err)
	}

	// Test running a simple tshark command (version)
	cmd, err := RunTSharkCommand(path, "-v")
	if err != nil {
		t.Errorf("Failed to create TShark command: %v", err)
	}

	// Execute the command
	output, err := cmd.Output()
	if err != nil {
		t.Errorf("Failed to run TShark command: %v", err)
	}

	// Check that we got some output
	if len(output) == 0 {
		t.Error("Expected non-empty output from TShark command")
	}
}

func TestGetTSharkVersionEmptyPath(t *testing.T) {
	// This test will be skipped if tshark is not installed
	if _, err := FindTShark(); err != nil {
		t.Skipf("Skipping test because tshark is not installed: %v", err)
	}

	// An empty path must be resolved via FindTShark, like every other function here.
	v, err := GetTSharkVersion("")
	if err != nil {
		t.Fatalf("GetTSharkVersion(\"\") failed: %v", err)
	}

	matched, _ := regexp.MatchString(`^v\d+\.\d+\.\d+$`, v)
	if !matched {
		t.Errorf("version %q does not match vX.Y.Z", v)
	}
}
