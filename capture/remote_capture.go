package capture

import (
	"fmt"
	"io"
	"strconv"
)

// RemoteCapture represents a capture on a remote machine running rpcapd.
type RemoteCapture struct {
	*LiveCapture
	RemoteHost      string
	RemoteInterface string
	RemotePort      int
}

// NewRemoteCapture creates a new RemoteCapture instance.
// Note: The remote machine should have rpcapd running in null authentication mode (-n).
// Be warned that the traffic is unencrypted!
func NewRemoteCapture(remoteHost, remoteInterface string, options ...func(*Capture)) (*RemoteCapture, error) {
	// Default remote port
	remotePort := 2002

	// Construct the rpcap interface string
	rpcapInterface := fmt.Sprintf("rpcap://%s:%d/%s", remoteHost, remotePort, remoteInterface)

	// Create a LiveCapture with the rpcap interface
	lc, err := NewLiveCapture([]string{rpcapInterface}, options...)
	if err != nil {
		return nil, err
	}

	// Create the RemoteCapture
	rc := &RemoteCapture{
		LiveCapture:     lc,
		RemoteHost:      remoteHost,
		RemoteInterface: remoteInterface,
		RemotePort:      remotePort,
	}

	return rc, nil
}

// WithRemotePort sets the remote port for the rpcapd service.
func WithRemotePort(port int) func(*RemoteCapture) {
	return func(rc *RemoteCapture) {
		rc.RemotePort = port

		// Update the interface string with the new port
		rpcapInterface := fmt.Sprintf("rpcap://%s:%d/%s", rc.RemoteHost, port, rc.RemoteInterface)
		rc.Interfaces = []string{rpcapInterface}
	}
}

// Start begins the remote capture process.
func (rc *RemoteCapture) Start() (stdout io.ReadCloser, stderr io.ReadCloser, err error) {
	// Verify the rpcap interface format
	if len(rc.Interfaces) != 1 || rc.Interfaces[0] == "" {
		// Reconstruct the interface if it's missing
		rpcapInterface := fmt.Sprintf("rpcap://%s:%d/%s", rc.RemoteHost, rc.RemotePort, rc.RemoteInterface)
		rc.Interfaces = []string{rpcapInterface}
	}

	// Use the LiveCapture's Start method
	return rc.LiveCapture.Start()
}

// String returns a string representation of the RemoteCapture.
func (rc *RemoteCapture) String() string {
	return fmt.Sprintf("RemoteCapture(host=%s, interface=%s, port=%s)",
		rc.RemoteHost, rc.RemoteInterface, strconv.Itoa(rc.RemotePort))
}
