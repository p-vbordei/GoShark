package capture

import (
	"io"
	"GoShark/goshark/tshark"
)

// PipeCapture represents a packet capture from an io.Reader (pipe).
type PipeCapture struct {
	Capture
	pipe io.Reader
}

// NewPipeCapture creates a new PipeCapture instance.
func NewPipeCapture(pipe io.Reader, options ...Option) *PipeCapture {
	c := &PipeCapture{
		Capture: Capture{
			TShark: tshark.NewTShark(),
		},
		pipe:    pipe,
	}

	for _, option := range options {
		option(&c.Capture)
	}

	return c
}

// Start begins the packet capture process from the pipe.
func (c *PipeCapture) Start() (stdout io.Reader, stderr io.Reader, err error) {
	c.Capture.SetCommandLineArgs("-r", "-") // Read from stdin
	return c.Capture.Start(c.pipe)
}

// Close closes the pipe (if it's a closer) and stops the capture.
func (c *PipeCapture) Close() error {
	if closer, ok := c.pipe.(io.Closer); ok {
		closer.Close()
	}
	return c.Capture.Stop()
}
