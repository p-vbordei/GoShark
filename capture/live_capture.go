package capture

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"GoShark/tshark"
)

// LiveCapture represents a live capture on a network interface.
type LiveCapture struct {
	*Capture
	Interfaces []string
	BPFFilter  string
}

// NewLiveCapture creates a new LiveCapture instance with the specified interfaces.
// If no interfaces are provided, all available interfaces will be used.
func NewLiveCapture(interfaces []string, options ...func(*Capture)) (*LiveCapture, error) {
	c := NewCapture(options...)

	lc := &LiveCapture{
		Capture: c,
	}

	// If no interfaces provided, get all available interfaces
	if len(interfaces) == 0 {
		allInterfaces, err := tshark.GetTSharkInterfaces(c.TSharkPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get interfaces: %w", err)
		}
		lc.Interfaces = allInterfaces
	} else {
		lc.Interfaces = interfaces
	}

	return lc, nil
}

// WithBPFFilter sets the BPF filter for the live capture.
func WithBPFFilter(filter string) func(*LiveCapture) {
	return func(lc *LiveCapture) {
		lc.BPFFilter = filter
	}
}

// VerifyCaptureParameters checks if the specified interfaces exist.
func (lc *LiveCapture) VerifyCaptureParameters() error {
	allInterfaces, err := tshark.GetAllTSharkInterfaceNames(lc.TSharkPath)
	if err != nil {
		return fmt.Errorf("failed to get interface names: %w", err)
	}

	allInterfacesLowercase := make(map[string]bool)
	for _, iface := range allInterfaces {
		allInterfacesLowercase[strings.ToLower(iface)] = true
	}

	for _, iface := range lc.Interfaces {
		// Skip validation for remote interfaces and numeric interfaces
		if strings.HasPrefix(iface, "rpcap://") || isNumeric(iface) {
			continue
		}

		if !allInterfacesLowercase[strings.ToLower(iface)] {
			return fmt.Errorf("interface '%s' does not exist, unable to initiate capture", iface)
		}
	}

	return nil
}

// isNumeric checks if a string is numeric.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// Start begins the live capture process.
func (lc *LiveCapture) Start() (stdout io.ReadCloser, stderr io.ReadCloser, err error) {
	// Verify interfaces exist
	if err := lc.VerifyCaptureParameters(); err != nil {
		return nil, nil, err
	}

	// Get dumpcap parameters
	dumpcapParams := lc.getDumpcapParameters()

	// Start dumpcap process
	dumpcapPath, err := tshark.GetDumpcapPath(lc.TSharkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get dumpcap path: %w", err)
	}

	dumpcapCmd := exec.Command(dumpcapPath, dumpcapParams...)

	// Get dumpcap stdout
	dumpcapStdout, err := dumpcapCmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get dumpcap stdout pipe: %w", err)
	}

	// Get dumpcap stderr for error logging
	_, err = dumpcapCmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get dumpcap stderr pipe: %w", err)
	}

	// Start dumpcap
	if err := dumpcapCmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start dumpcap: %w", err)
	}

	// Get tshark parameters
	tsharkParams, err := lc.getTSharkArgs()
	if err != nil {
		dumpcapCmd.Process.Kill()
		return nil, nil, fmt.Errorf("failed to get tshark parameters: %w", err)
	}

	// Add -i - to read from stdin
	tsharkParams = append(tsharkParams, "-i", "-")

	// Start tshark process
	tsharkPath, err := tshark.GetTSharkPath(lc.TSharkPath)
	if err != nil {
		dumpcapCmd.Process.Kill()
		return nil, nil, fmt.Errorf("failed to get tshark path: %w", err)
	}

	tsharkCmd := exec.Command(tsharkPath, tsharkParams...)

	// Connect dumpcap stdout to tshark stdin
	tsharkCmd.Stdin = dumpcapStdout

	// Get tshark stdout
	tsharkStdout, err := tsharkCmd.StdoutPipe()
	if err != nil {
		dumpcapCmd.Process.Kill()
		return nil, nil, fmt.Errorf("failed to get tshark stdout pipe: %w", err)
	}

	// Get tshark stderr
	tsharkStderr, err := tsharkCmd.StderrPipe()
	if err != nil {
		dumpcapCmd.Process.Kill()
		return nil, nil, fmt.Errorf("failed to get tshark stderr pipe: %w", err)
	}

	// Start tshark
	if err := tsharkCmd.Start(); err != nil {
		dumpcapCmd.Process.Kill()
		return nil, nil, fmt.Errorf("failed to start tshark: %w", err)
	}

	// Store the tshark command
	lc.cmd = tsharkCmd

	return tsharkStdout, tsharkStderr, nil
}

// getDumpcapParameters returns the parameters for dumpcap.
func (lc *LiveCapture) getDumpcapParameters() []string {
	params := []string{"-q"} // Don't report packet counts

	// Add BPF filter if specified
	if lc.BPFFilter != "" {
		params = append(params, "-f", lc.BPFFilter)
	}

	// Add monitor mode if enabled
	if lc.MonitorMode {
		params = append(params, "-I")
	}

	// Add interfaces
	for _, iface := range lc.Interfaces {
		params = append(params, "-i", iface)
	}

	// Write to stdout
	params = append(params, "-w", "-")

	return params
}
