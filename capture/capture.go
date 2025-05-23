package capture

import (
	"io"
	"os/exec"
	"strconv"

	"GoShark/tshark"
)

// Capture represents a base for different tshark capture types.
type Capture struct {
	DisplayFilter string
	CaptureFilter string
	TSharkPath    string
	UseJSON       bool
	IncludeRaw    bool
	Decodes       []string
	EncryptionKeys []string
	OverridePreferences []string
	PacketCount   int
	
	cmd *exec.Cmd
}

// NewCapture creates a new base Capture object.
func NewCapture(options ...func(*Capture)) *Capture {
	c := &Capture{
		UseJSON: true, // Default to JSON output for easier parsing
	}

	for _, option := range options {
		option(c)
	}
	return c
}

// WithDisplayFilter sets the display filter for the capture.
func WithDisplayFilter(filter string) func(*Capture) { 
	return func(c *Capture) {
		c.DisplayFilter = filter
	}
}

// WithCaptureFilter sets the capture filter for the capture.
func WithCaptureFilter(filter string) func(*Capture) {
	return func(c *Capture) {
		c.CaptureFilter = filter
	}
}

// WithTSharkPath sets the path to the tshark executable.
func WithTSharkPath(path string) func(*Capture) {
	return func(c *Capture) {
		c.TSharkPath = path
	}
}

// WithUseJSON sets whether to use JSON output from tshark.
func WithUseJSON(useJSON bool) func(*Capture) {
	return func(c *Capture) {
		c.UseJSON = useJSON
	}
}

// WithIncludeRaw sets whether to include raw packet data in the output.
func WithIncludeRaw(includeRaw bool) func(*Capture) {
	return func(c *Capture) {
		c.IncludeRaw = includeRaw
	}
}

// WithDecodes adds decode-as rules.
func WithDecodes(decodes ...string) func(*Capture) {
	return func(c *Capture) {
		c.Decodes = append(c.Decodes, decodes...)
	}
}

// WithEncryptionKeys adds encryption keys.
func WithEncryptionKeys(keys ...string) func(*Capture) {
	return func(c *Capture) {
		c.EncryptionKeys = append(c.EncryptionKeys, keys...)
	}
}

// WithOverridePreferences adds override preferences.
func WithOverridePreferences(prefs ...string) func(*Capture) {
	return func(c *Capture) {
		c.OverridePreferences = append(c.OverridePreferences, prefs...)
	}
}

// WithPacketCount sets the maximum number of packets to capture.
func WithPacketCount(count int) func(*Capture) {
	return func(c *Capture) {
		c.PacketCount = count
	}
}

// getTSharkArgs constructs the tshark command arguments based on the Capture configuration.
func (c *Capture) getTSharkArgs() ([]string, error) {
	args := []string{"-l", "-n"}

	if c.PacketCount > 0 {
		args = append(args, "-c", strconv.Itoa(c.PacketCount))
	}

	if c.UseJSON {
		// Check tshark version for JSON support and --no-duplicate-keys
		// For now, assume modern tshark that supports JSON and --no-duplicate-keys
		args = append(args, "-T", "json", "--no-duplicate-keys")
	} else {
		// Default to PDML if not JSON
		args = append(args, "-T", "pdml")
	}

	if c.DisplayFilter != "" {
		// In pyshark, it uses -Y for tshark >= 1.10.0 and -R for older.
		// For simplicity, we'll assume a modern tshark and use -Y.
		args = append(args, "-Y", c.DisplayFilter)
	}

	if c.CaptureFilter != "" {
		args = append(args, "-f", c.CaptureFilter)
	}

	for _, decode := range c.Decodes {
		args = append(args, "-d", decode)
	}

	for _, key := range c.EncryptionKeys {
		args = append(args, "-o", "wlan.enable_decryption:TRUE", "-o", "wlan.wep_keys:"+key)
	}

	for _, pref := range c.OverridePreferences {
		args = append(args, "-o", pref)
	}

	return args, nil
}

// Start starts the tshark capture process.
// It returns readers for stdout and stderr.
func (c *Capture) Start() (io.ReadCloser, io.ReadCloser, error) {
	args, err := c.getTSharkArgs()
	if err != nil {
		return nil, nil, err
	}

	cmd, err := tshark.RunTSharkCommand(c.TSharkPath, args...)
	if err != nil {
		return nil, nil, err
	}
	c.cmd = cmd

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

// Stop stops the tshark capture process.
func (c *Capture) Stop() error {
	if c.cmd != nil && c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}
	return nil
}

// Wait waits for the tshark command to finish.
func (c *Capture) Wait() error {
	if c.cmd != nil {
		return c.cmd.Wait()
	}
	return nil
}
