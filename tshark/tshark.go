package tshark

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"regexp"
	"strings"
	"sync"
	"time"

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
	return semver.Compare("v"+v1, "v"+v2)
}

// TSharkProcess represents a running TShark process.
type TSharkProcess struct {
	cmd       *exec.Cmd
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	ctx       context.Context
	cancel    context.CancelFunc
	mutex     sync.Mutex
	isRunning bool
	timeout   time.Duration
}

// TSharkProcessOptions contains options for creating a new TShark process.
type TSharkProcessOptions struct {
	TSharkPath      string        // Path to the tshark executable
	Args           []string      // Command-line arguments for tshark
	Timeout        time.Duration // Timeout for the process
	CaptureTimeout time.Duration // Timeout for the capture itself
}

// NewTSharkProcess creates a new TShark process with the given options.
func NewTSharkProcess(options TSharkProcessOptions) (*TSharkProcess, error) {
	// Use default tshark path if not specified
	tsharkPath := options.TSharkPath
	if tsharkPath == "" {
		var err error
		tsharkPath, err = FindTShark()
		if err != nil {
			return nil, err
		}
	}

	// Create a context with timeout if specified
	ctx := context.Background()
	var cancel context.CancelFunc
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// Create the command
	cmd := exec.CommandContext(ctx, tsharkPath, options.Args...)

	// Get stdout and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	return &TSharkProcess{
		cmd:       cmd,
		stdout:    stdout,
		stderr:    stderr,
		ctx:       ctx,
		cancel:    cancel,
		isRunning: false,
		timeout:   options.CaptureTimeout,
	}, nil
}

// Start starts the TShark process.
func (p *TSharkProcess) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.isRunning {
		return fmt.Errorf("process already running")
	}

	err := p.cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start tshark process: %w", err)
	}

	p.isRunning = true

	// If a capture timeout is set, start a goroutine to stop the process after the timeout
	if p.timeout > 0 {
		go func() {
			time.Sleep(p.timeout)
			p.Stop()
		}()
	}

	return nil
}

// Stop stops the TShark process.
func (p *TSharkProcess) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.isRunning {
		return nil // Already stopped
	}

	// Cancel the context to stop the process
	p.cancel()

	// Wait for the process to exit
	err := p.cmd.Wait()
	p.isRunning = false

	if err != nil && err.Error() != "context canceled" {
		return fmt.Errorf("error waiting for tshark process to exit: %w", err)
	}

	return nil
}

// IsRunning returns whether the TShark process is running.
func (p *TSharkProcess) IsRunning() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.isRunning
}

// GetStdout returns the stdout pipe of the TShark process.
func (p *TSharkProcess) GetStdout() io.ReadCloser {
	return p.stdout
}

// GetStderr returns the stderr pipe of the TShark process.
func (p *TSharkProcess) GetStderr() io.ReadCloser {
	return p.stderr
}

// Wait waits for the TShark process to exit.
func (p *TSharkProcess) Wait() error {
	err := p.cmd.Wait()

	p.mutex.Lock()
	p.isRunning = false
	p.mutex.Unlock()

	return err
}

// GetTSharkInterfaces returns a list of available network interfaces from TShark.
func GetTSharkInterfaces(tsharkPath string) ([]string, error) {
	// Use default tshark path if not specified
	if tsharkPath == "" {
		var err error
		tsharkPath, err = FindTShark()
		if err != nil {
			return nil, err
		}
	}

	// Run tshark -D to get interface list
	cmd := exec.Command(tsharkPath, "-D")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run tshark -D: %w", err)
	}

	// Parse the output
	lines := strings.Split(string(output), "\n")
	interfaces := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format is usually: "1. eth0 (Network interface eth0)"
		parts := strings.SplitN(line, ".", 2)
		if len(parts) < 2 {
			continue
		}

		interfacePart := strings.TrimSpace(parts[1])
		interfaceName := strings.SplitN(interfacePart, " ", 2)[0]
		interfaces = append(interfaces, interfaceName)
	}

	return interfaces, nil
}

// GetAllTSharkInterfaceNames returns a list of all interface names from TShark.
func GetAllTSharkInterfaceNames(tsharkPath string) ([]string, error) {
	interfaces, err := GetTSharkInterfaces(tsharkPath)
	if err != nil {
		return nil, err
	}

	return interfaces, nil
}

// GetDumpcapPath returns the path to the dumpcap executable.
func GetDumpcapPath(tsharkPath string) (string, error) {
	// Use default tshark path if not specified
	if tsharkPath == "" {
		var err error
		tsharkPath, err = FindTShark()
		if err != nil {
			return "", err
		}
	}

	// Dumpcap is usually in the same directory as tshark
	tsharkDir := strings.TrimSuffix(tsharkPath, "tshark")
	if runtime.GOOS == "windows" {
		tsharkDir = strings.TrimSuffix(tsharkPath, "tshark.exe")
		return tsharkDir + "dumpcap.exe", nil
	}

	return tsharkDir + "dumpcap", nil
}

// GetTSharkPath returns the path to the tshark executable.
func GetTSharkPath(tsharkPath string) (string, error) {
	if tsharkPath != "" {
		return tsharkPath, nil
	}
	return FindTShark()
}

// RunTSharkCommand creates and returns an exec.Cmd for a tshark command.
func RunTSharkCommand(tsharkPath string, args ...string) (*exec.Cmd, error) {
	// If tshark path is not provided, find it
	if tsharkPath == "" {
		var err error
		tsharkPath, err = FindTShark()
		if err != nil {
			return nil, err
		}
	}

	// Create the command
	cmd := exec.Command(tsharkPath, args...)
	return cmd, nil
}
