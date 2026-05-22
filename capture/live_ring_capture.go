package capture

import (
	"fmt"
	"io"
	"strconv"
)

// LiveRingCapture represents a live capture with ring buffer functionality.
type LiveRingCapture struct {
	*LiveCapture
	RingFileSize  int    // Size of the ring file in kB
	NumRingFiles  int    // Number of ring files to keep
	RingFileName  string // Name of the ring file
}

// NewLiveRingCapture creates a new LiveRingCapture instance.
func NewLiveRingCapture(interfaces []string, options ...Option) (*LiveRingCapture, error) {
	// Create the base LiveCapture
	lc, err := NewLiveCapture(interfaces, options...)
	if err != nil {
		return nil, err
	}

	// Create the LiveRingCapture with default values
	lrc := &LiveRingCapture{
		LiveCapture:  lc,
		RingFileSize: 1024,
		NumRingFiles: 1,
		RingFileName: "/tmp/goshark.pcap",
	}

	for _, option := range options {
		option(lrc)
	}

	return lrc, nil
}

// WithRingFileSize sets the size of the ring file in kB.
func WithRingFileSize(size int) Option {
	return func(v interface{}) {
		if lrc, ok := v.(*LiveRingCapture); ok {
			lrc.RingFileSize = size
		}
	}
}

// WithNumRingFiles sets the number of ring files to keep.
func WithNumRingFiles(num int) Option {
	return func(v interface{}) {
		if lrc, ok := v.(*LiveRingCapture); ok {
			lrc.NumRingFiles = num
		}
	}
}

// WithRingFileName sets the name of the ring file.
func WithRingFileName(name string) Option {
	return func(v interface{}) {
		if lrc, ok := v.(*LiveRingCapture); ok {
			lrc.RingFileName = name
		}
	}
}

// Start begins the live ring capture process.
func (lrc *LiveRingCapture) Start() (stdout io.ReadCloser, stderr io.ReadCloser, err error) {
	// Get the base tshark arguments
	tsharkArgs, err := lrc.getTSharkArgs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tshark arguments: %w", err)
	}

	// Add ring buffer parameters
	tsharkArgs = append(tsharkArgs,
		"-b", "filesize:"+strconv.Itoa(lrc.RingFileSize),
		"-b", "files:"+strconv.Itoa(lrc.NumRingFiles),
		"-w", lrc.RingFileName,
		"-P", // Use pcap format
		"-V", // Verbose output
	)

	// Add interface parameters
	for _, iface := range lrc.Interfaces {
		tsharkArgs = append(tsharkArgs, "-i", iface)
	}

	// Start the capture process
	return lrc.Capture.startWithArgs(tsharkArgs)
}

// getDumpcapParameters returns the parameters for dumpcap.
func (lrc *LiveRingCapture) getDumpcapParameters() []string {
	// Get the base dumpcap parameters
	params := lrc.LiveCapture.getDumpcapParameters()

	// Add the -P flag for pcap format
	params = append(params, "-P")

	return params
}
