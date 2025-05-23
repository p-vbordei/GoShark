package capture

import (
	"fmt"
)

// RemoteCapture represents a packet capture from a remote machine running rpcapd.
type RemoteCapture struct {
	*LiveCapture
}

// NewRemoteCapture creates a new RemoteCapture instance.
// It connects to a remote host and captures packets from the specified interface.
// Note: The remote machine should have rpcapd running in null authentication mode (-n).
// Be warned that the traffic is unencrypted!
func NewRemoteCapture(remoteHost, remoteInterface string, remotePort int, options ...Option) *RemoteCapture {
	interfaceStr := fmt.Sprintf("rpcap://%s:%d/%s", remoteHost, remotePort, remoteInterface)
	liveCapture := NewLiveCapture(interfaceStr, options...)
	return &RemoteCapture{
		LiveCapture: liveCapture,
	}
}
