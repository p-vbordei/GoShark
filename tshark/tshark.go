package tshark

import (
	"os"
	"os/exec"
	"runtime"
	"path/filepath"
	"regexp"
)

// TSharkNotFoundException is an error returned when the tshark executable is not found.
type TSharkNotFoundException struct {
	Message string
}

func (e *TSharkNotFoundException) Error() string {
	return e.Message
}

// TSharkVersionException is returned when tshark version cannot be parsed.
type TSharkVersionException struct { Msg string }

func (e *TSharkVersionException) Error() string {
	return "tshark version error: " + e.Msg
}

// TSharkCommandException is returned when a tshark command fails to execute.
type TSharkCommandException struct { Msg string }

func (e *TSharkCommandException) Error() string {
	return "tshark command error: " + e.Msg
}

// getTSharkPath finds the path of the tshark executable.
// It searches common locations based on the operating system.
func getTSharkPath(tsharkPath string) (string, error) {
	possiblePaths := []string{}

	// Add user provided path first
	if tsharkPath != "" {
		var userTsharkPath string
		if runtime.GOOS == "windows" {
			userTsharkPath = filepath.Join(filepath.Dir(tsharkPath), "tshark.exe")
		} else {
			userTsharkPath = filepath.Join(filepath.Dir(tsharkPath), "tshark")
		}
		possiblePaths = append(possiblePaths, userTsharkPath)
	}

	// Common paths for Windows
	if runtime.GOOS == "windows" {
		programFiles := os.Getenv("ProgramFiles")
		if programFiles != "" {
			possiblePaths = append(possiblePaths, filepath.Join(programFiles, "Wireshark", "tshark.exe"))
		}
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		if programFilesX86 != "" {
			possiblePaths = append(possiblePaths, filepath.Join(programFilesX86, "Wireshark", "tshark.exe"))
		}
	} else if runtime.GOOS == "darwin" { // Common path for macOS
		possiblePaths = append(possiblePaths, "/Applications/Wireshark.app/Contents/MacOS/tshark")
	} else { // Common paths for Linux/Unix
		pathEnv := os.Getenv("PATH")
		if pathEnv == "" {
			pathEnv = "/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin"
		}
		for _, p := range filepath.SplitList(pathEnv) {
			possiblePaths = append(possiblePaths, filepath.Join(p, "tshark"))
		}
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Fallback to looking in PATH using exec.LookPath
	if p, err := exec.LookPath("tshark"); err == nil {
		return p, nil
	}

	return "", &TSharkNotFoundException{Message: "tshark executable not found"}
}

// GetProcessPath finds the path of the tshark executable.
// It mirrors the functionality of pyshark's get_process_path.
func GetProcessPath(tsharkPath string) (string, error) {
	return getTSharkPath(tsharkPath)
}

// splitLines splits a string by newline characters.
func splitLines(s string) []string {
	return regexp.MustCompile(`\r?\n`).Split(s, -1)
}

// GetTSharkVersion executes 'tshark -v' and parses the output to get the version.
func GetTSharkVersion(tsharkPath string) (string, error) {
	path, err := GetProcessPath(tsharkPath)
	if err != nil {
		return "", err
	}

	cmd := exec.Command(path, "-v")
	output, err := cmd.Output()
	if err != nil {
		return "", &TSharkVersionException{Msg: "failed to execute tshark -v: " + err.Error()}
	}

	versionOutput := string(output)
	lines := splitLines(versionOutput)
	if len(lines) == 0 {
		return "", &TSharkVersionException{Msg: "empty output from tshark -v"}
	}

	// The version is usually on the first line, e.g., "TShark (Wireshark) 3.4.6 (Git v3.4.6...)"
	firstLine := lines[0]
	re := regexp.MustCompile(`\d+\.\d+\.\d+`)
	match := re.FindString(firstLine)

	if match == "" {
		return "", &TSharkVersionException{Msg: "unable to parse version from: " + firstLine}
	}

	return match, nil
}

// RunTSharkCommand prepares the tshark command with the given arguments.
// It returns the exec.Cmd object, which can then be started by the caller.
func RunTSharkCommand(tsharkPath string, args ...string) (*exec.Cmd, error) {
	path, err := GetProcessPath(tsharkPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(path, args...)

	return cmd, nil
}
