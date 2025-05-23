package capture

import (
	"io"
	"GoShark/tshark"
)

// LiveCapture represents a live packet capture from a network interface.
type LiveCapture struct {
	*Capture
	Interface   string
	MonitorMode bool
	// Add other live capture specific fields like bpf_filter, etc.
}

// NewLiveCapture creates a new LiveCapture object.
func NewLiveCapture(iface string, options ...func(*Capture)) *LiveCapture {
	c := NewCapture(options...)
	return &LiveCapture{
		Capture:   c,
		Interface: iface,
	}
}

// Start starts the live capture process.
// It returns readers for stdout and stderr.
func (lc *LiveCapture) Start() (io.ReadCloser, io.ReadCloser, error) {
	args, err := lc.Capture.getTSharkArgs()
	if err != nil {
		return nil, nil, err
	}

	// Add live capture specific arguments
	args = append(args, "-i", lc.Interface)
	if lc.MonitorMode {
		args = append(args, "-I")
	}

	cmd, err := tshark.RunTSharkCommand(lc.Capture.TSharkPath, args...)
	if err != nil {
		return nil, nil, err
	}
	lc.Capture.cmd = cmd

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, nil, err
	}

	return stdout, stderr, nil
}
