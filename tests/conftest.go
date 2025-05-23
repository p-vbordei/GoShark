package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDataPath returns the absolute path to the test data directory.
func TestDataPath() string {
	_, filename, _, _ := runtime.Caller(0)
	dirPath := filepath.Dir(filename)
	return filepath.Join(dirPath, "data")
}

// GetTestPcapPath returns the absolute path to a test PCAP file.
func GetTestPcapPath(filename string) string {
	return filepath.Join(TestDataPath(), filename)
}

// GetTestJSONPath returns the absolute path to a test JSON file.
func GetTestJSONPath(filename string) string {
	return filepath.Join(TestDataPath(), "json", filename)
}

// GetTestXMLPath returns the absolute path to a test XML file.
func GetTestXMLPath(filename string) string {
	return filepath.Join(TestDataPath(), "xml", filename)
}

// GetTestEKPath returns the absolute path to a test EK file.
func GetTestEKPath(filename string) string {
	return filepath.Join(TestDataPath(), "ek", filename)
}

// SkipIfNoTShark skips the test if TShark is not available.
func SkipIfNoTShark(t *testing.T) {
	// Check if tshark is available in PATH
	_, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("TShark not found in PATH, skipping test")
	}
}

// CreateTempPcapFile creates a temporary PCAP file for testing.
func CreateTempPcapFile(t *testing.T, sourceFile string) string {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "goshark-test-*.pcap")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	tmpFile.Close()

	// Copy the source file to the temporary file
	sourceData, err := os.ReadFile(GetTestPcapPath(sourceFile))
	if err != nil {
		t.Fatalf("Failed to read source file: %v", err)
	}

	err = os.WriteFile(tmpFile.Name(), sourceData, 0644)
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}

	// Register cleanup function
	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})

	return tmpFile.Name()
}

// CreateTestDataDirs creates the necessary subdirectories in the test data directory.
func CreateTestDataDirs() error {
	dirs := []string{
		TestDataPath(),
		filepath.Join(TestDataPath(), "json"),
		filepath.Join(TestDataPath(), "xml"),
		filepath.Join(TestDataPath(), "ek"),
	}

	for _, dir := range dirs {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}

	return nil
}
