package tshark

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"path/filepath"
	"regexp"
	"strings"
)

// TSharkNotFoundException is an error returned when the tshark executable is not found.
type TSharkNotFoundException struct {
	Message string
}

func (e *TSharkNotFoundException) Error() string {
	return e.Message
}

// GetProcessPath finds the path of the tshark executable.
// It mirrors the functionality of pyshark's get_process_path.
func GetProcessPath(tsharkPath string) (string, error) {
	possiblePaths := []string{}

	// Add user provided path to the search list
	if tsharkPath != "" {
		var userTSharkPath string
		if runtime.GOOS == "windows" {
			userTSharkPath = filepath.Join(filepath.Dir(tsharkPath), "tshark.exe")
		} else {
			userTSharkPath = filepath.Join(filepath.Dir(tsharkPath), "tshark")
		}
		possiblePaths = append([]string{userTSharkPath}, possiblePaths...)
	}

	// Common paths based on OS
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles"} {
			programFiles := os.Getenv(env)
			if programFiles != "" {
				possiblePaths = append(possiblePaths, filepath.Join(programFiles, "Wireshark", "tshark.exe"))
			}
		}
	case "darwin":
		possiblePaths = append(possiblePaths, "/Applications/Wireshark.app/Contents/MacOS/tshark")
		fallthrough // Also check common Unix paths
	case "linux":
		osPath := os.Getenv("PATH")
		if osPath == "" {
			osPath = "/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin"
		}
		for _, path := range filepath.SplitList(osPath) {
			possiblePaths = append(possiblePaths, filepath.Join(path, "tshark"))
		}
	}
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", &TSharkNotFoundException{Message: fmt.Sprintf("TShark not found. Searched these paths: %v", possiblePaths)}
}

// splitLines splits a string by newline characters.
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

// GetTSharkVersion gets the tshark version.
func GetTSharkVersion(tsharkPath string) (string, error) {
	path, err := GetProcessPath(tsharkPath)
	if err != nil {
		return "", err
	}

	cmd := exec.Command(path, "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run tshark -v: %w", err)
	}

	// Parse version from output
	// This is a simplified version and might need more robust parsing
	versionOutput := string(output)
	lines := splitLines(versionOutput)
	if len(lines) == 0 {
		return "", fmt.Errorf("empty output from tshark -v")
	}
	
	// Assuming the version is in the first line, similar to pyshark's approach
	// A more robust regex might be needed here for production use
	versionLine := lines[0]
	// Example: Wireshark 3.4.6 (Git v3.4.6-0-g7789d20c)
	// We need to extract 3.4.6
	// This regex matches one or more digits, followed by a dot, repeated at least twice.
	// It captures the entire version string.
	re := regexp.MustCompile(`\d+\.\d+\.\d+`)
	match := re.FindString(versionLine)
	if match == "" {
		return "", fmt.Errorf("unable to parse TShark version from: %s", versionLine)
	}

	return match, nil
}
