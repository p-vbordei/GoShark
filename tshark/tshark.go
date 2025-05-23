package tshark

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// TSharkNotFoundException is returned when the TShark executable cannot be found.
type TSharkNotFoundException struct {
	Message string
}

func (e *TSharkNotFoundException) Error() string {
	return e.Message
}

// TSharkVersionException is returned when there's an issue with the TShark version.
type TSharkVersionException struct {
	Message string
}

func (e *TSharkVersionException) Error() string {
	return e.Message
}

// FindTShark attempts to locate the tshark executable on the system.
// It checks common paths and the system's PATH environment variable.
func FindTShark() (string, error) {
	// Check if TSHARK_PATH environment variable is set
	if tsharkPath := os.Getenv("TSHARK_PATH"); tsharkPath != "" {
		if _, err := os.Stat(tsharkPath); err == nil {
			return tsharkPath, nil
		}
	}

	// Common installation paths
	var possiblePaths []string
	if runtime.GOOS == "windows" {
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		if programFiles != "" {
			possiblePaths = append(possiblePaths, fmt.Sprintf("%s\\Wireshark\\tshark.exe", programFiles))
		}
		if programFilesX86 != "" {
			possiblePaths = append(possiblePaths, fmt.Sprintf("%s\\Wireshark\\tshark.exe", programFilesX86))
		}
	} else { // Linux, macOS, etc.
		possiblePaths = append(possiblePaths,
			"/usr/bin/tshark",
			"/usr/local/bin/tshark",
			"/opt/homebrew/bin/tshark", // For macOS Homebrew
			"/usr/sbin/tshark",
		)
	}

	// Check common paths
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Check system PATH
	tsharkPath, err := exec.LookPath("tshark")
	if err == nil {
		return tsharkPath, nil
	}

	return "", &TSharkNotFoundException{Message: "tshark executable not found in common paths or system PATH. Please ensure it is installed and accessible."}
}

// GetTSharkVersion retrieves the version of the TShark executable.
func GetTSharkVersion(tsharkPath string) (string, error) {
	cmd := exec.Command(tsharkPath, "-v")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run tshark -v: %w", err)
	}

	// The version string is usually the first line, e.g., "TShark (Wireshark) 3.4.8 (Git v3.4.8...)"
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return "", &TSharkVersionException{Message: "could not parse tshark version output"}
	}

	firstLine := lines[0]
	// Extract version number using regex or string manipulation
	// Example: "TShark (Wireshark) 3.4.8 (Git v3.4.8...)" -> "3.4.8"
	re := regexp.MustCompile(`\d+\.\d+\.\d+`)
	match := re.FindString(firstLine)
	if match == "" {
		return "", &TSharkVersionException{Message: "could not find version number in tshark output"}
	}

	// Prepend 'v' to make it a valid semver string for comparison
	return "v" + match, nil
}

// CompareTSharkVersions compares two TShark versions using semantic versioning.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareTSharkVersions(v1, v2 string) int {
	return semver.Compare(v1, v2)
}
