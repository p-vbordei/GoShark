package capture

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/p-vbordei/GoShark/packet"
	"github.com/p-vbordei/GoShark/tshark"
)

// LiveCapture represents a live capture on a network interface.
type LiveCapture struct {
	*Capture
	Interfaces []string
	BPFFilter  string
}

// NewLiveCapture creates a new LiveCapture instance with the specified interfaces.
// If no interfaces are provided, all available interfaces will be used.
func NewLiveCapture(interfaces []string, options ...Option) (*LiveCapture, error) {
	lc := &LiveCapture{
		Capture: &Capture{
			UseJSON: true,
		},
	}

	for _, option := range options {
		option(lc)
	}

	// If no interfaces provided, get all available interfaces
	if len(interfaces) == 0 {
		allInterfaces, err := tshark.GetTSharkInterfaces(lc.TSharkPath)
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
func WithBPFFilter(filter string) Option {
	return func(v interface{}) {
		if lc, ok := v.(*LiveCapture); ok {
			lc.BPFFilter = filter
		} else if rc, ok := v.(*RemoteCapture); ok && rc.LiveCapture != nil {
			rc.LiveCapture.BPFFilter = filter
		} else if lrc, ok := v.(*LiveRingCapture); ok && lrc.LiveCapture != nil {
			lrc.LiveCapture.BPFFilter = filter
		}
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

	// Discard dumpcap's stderr. The pipe must still be drained — an unread,
	// full stderr pipe would block dumpcap — so io.Discard is wired up via the
	// copier goroutine os/exec starts for a non-*os.File writer.
	dumpcapCmd.Stderr = io.Discard

	// Start dumpcap
	if err := dumpcapCmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start dumpcap: %w", err)
	}

	// cleanupDumpcap kills and reaps dumpcap. The error paths below use it so a
	// failed startup never leaves dumpcap behind as a zombie.
	cleanupDumpcap := func() {
		dumpcapCmd.Process.Kill()
		_ = dumpcapCmd.Wait()
	}

	// Get tshark parameters
	tsharkParams, err := lc.getTSharkArgs()
	if err != nil {
		cleanupDumpcap()
		return nil, nil, fmt.Errorf("failed to get tshark parameters: %w", err)
	}

	// Add -i - to read from stdin
	tsharkParams = append(tsharkParams, "-i", "-")

	// Start tshark process
	tsharkPath, err := tshark.GetTSharkPath(lc.TSharkPath)
	if err != nil {
		cleanupDumpcap()
		return nil, nil, fmt.Errorf("failed to get tshark path: %w", err)
	}

	tsharkCmd := exec.Command(tsharkPath, tsharkParams...)

	// Connect dumpcap stdout to tshark stdin
	tsharkCmd.Stdin = dumpcapStdout

	// Get tshark stdout
	tsharkStdout, err := tsharkCmd.StdoutPipe()
	if err != nil {
		cleanupDumpcap()
		return nil, nil, fmt.Errorf("failed to get tshark stdout pipe: %w", err)
	}

	// Get tshark stderr
	tsharkStderr, err := tsharkCmd.StderrPipe()
	if err != nil {
		cleanupDumpcap()
		return nil, nil, fmt.Errorf("failed to get tshark stderr pipe: %w", err)
	}

	// Start tshark
	if err := tsharkCmd.Start(); err != nil {
		cleanupDumpcap()
		return nil, nil, fmt.Errorf("failed to start tshark: %w", err)
	}

	// Store both commands so Stop can kill and reap dumpcap as well as tshark.
	lc.dumpcapCmd = dumpcapCmd
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

// SniffContinuously sniffs packets from the live capture and streams them on a channel.
func (lc *LiveCapture) SniffContinuously(ctx context.Context) (<-chan *packet.Packet, error) {
	stdout, stderr, err := lc.Start()
	if err != nil {
		return nil, err
	}
	return lc.sniffStream(ctx, stdout, stderr)
}

// ApplyOnPackets applies the callback to all captured packets.
func (lc *LiveCapture) ApplyOnPackets(callback func(*packet.Packet) bool, ctx context.Context) error {
	return lc.Capture.ApplyOnPackets(callback, ctx, func() (io.ReadCloser, io.ReadCloser, error) {
		return lc.Start()
	})
}
