package capture

import (
	"fmt"
	"io"
	"os/exec"
	"strconv"

	"GoShark/goshark/tshark"
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
	Snaplen       int
	Promiscuous   bool
	MonitorMode   bool
	
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

// WithDisplayFilter sets the Wireshark display filter for the capture (e.g., "http.request").
// Corresponds to tshark's -Y flag.
func WithDisplayFilter(filter string) func(*Capture) { 
	return func(c *Capture) {
		c.DisplayFilter = filter
	}
}

// WithCaptureFilter sets the BPF capture filter for the capture (e.g., "tcp port 80").
// Corresponds to tshark's -f flag.
func WithCaptureFilter(filter string) func(*Capture) {
	return func(c *Capture) {
		c.CaptureFilter = filter
	}
}

// WithTSharkPath sets the absolute path to the tshark executable.
func WithTSharkPath(path string) func(*Capture) {
	return func(c *Capture) {
		c.TSharkPath = path
	}
}

// WithUseJSON sets whether to use JSON output from tshark. If false, PDML is used.
// Corresponds to tshark's -T json or -T pdml flags.
func WithUseJSON(useJSON bool) func(*Capture) {
	return func(c *Capture) {
		c.UseJSON = useJSON
	}
}

// WithIncludeRaw sets whether to include raw packet data in the output. (Note: tshark JSON often includes raw data by default).
func WithIncludeRaw(includeRaw bool) func(*Capture) {
	return func(c *Capture) {
		c.IncludeRaw = includeRaw
	}
}

// WithDecodes adds decode-as rules (e.g., "tcp.port==8888,http").
// Corresponds to tshark's -d flag.
func WithDecodes(decodes ...string) func(*Capture) {
	return func(c *Capture) {
		c.Decodes = append(c.Decodes, decodes...)
	}
}

// WithEncryptionKeys adds WEP/WPA/WPA2 encryption keys (e.g., "wpa-pwd:password:ssid").
// Corresponds to tshark's -o wlan.wep_keys flag.
func WithEncryptionKeys(keys ...string) func(*Capture) {
	return func(c *Capture) {
		c.EncryptionKeys = append(c.EncryptionKeys, keys...)
	}
}

// WithOverridePreferences adds override preferences (e.g., "tcp.port:80").
// Corresponds to tshark's -o flag.
func WithOverridePreferences(prefs ...string) func(*Capture) {
	return func(c *Capture) {
		c.OverridePreferences = append(c.OverridePreferences, prefs...)
	}
}

// WithPacketCount sets the maximum number of packets to capture. 0 means unlimited.
// Corresponds to tshark's -c flag.
func WithPacketCount(count int) func(*Capture) {
	return func(c *Capture) {
		c.PacketCount = count
	}
}

// WithSnaplen sets the maximum number of bytes to capture per packet. 0 means unlimited.
// Corresponds to tshark's -s flag.
func WithSnaplen(snaplen int) func(*Capture) {
	return func(c *Capture) {
		c.Snaplen = snaplen
	}
}

// WithPromiscuous sets whether to capture in promiscuous mode. True by default in tshark.
// Corresponds to tshark's -p flag (disables promiscuous mode if -p is present).
func WithPromiscuous(promiscuous bool) func(*Capture) {
	return func(c *Capture) {
		c.Promiscuous = promiscuous
	}
}

// WithMonitorMode sets whether to capture in monitor mode. Applicable to wireless interfaces.
// Corresponds to tshark's -I flag.
func WithMonitorMode(monitorMode bool) func(*Capture) {
	return func(c *Capture) {
		c.MonitorMode = monitorMode
	}
}

// getTSharkArgs constructs the tshark command arguments based on the Capture configuration.
func (c *Capture) getTSharkArgs() ([]string, error) {
	args := []string{"-l", "-n"}

	if c.PacketCount > 0 {
		args = append(args, "-c", strconv.Itoa(c.PacketCount))
	}

	if c.CaptureFilter != "" {
		args = append(args, "-f", c.CaptureFilter)
	}

	if c.DisplayFilter != "" {
		args = append(args, "-Y", c.DisplayFilter)
	}

	if c.Snaplen > 0 {
		args = append(args, "-s", strconv.Itoa(c.Snaplen))
	}

	if !c.Promiscuous {
		args = append(args, "-p")
	}

	if c.MonitorMode {
		args = append(args, "-I")
	}

	if c.UseJSON {
		// Check tshark version for JSON support and --no-duplicate-keys
		// For now, assume modern tshark that supports JSON and --no-duplicate-keys
		args = append(args, "-T", "json", "--no-duplicate-keys")
	} else {
		// Default to PDML if not JSON
		args = append(args, "-T", "pdml")
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
	if c.cmd == nil || c.cmd.Process == nil {
		return fmt.Errorf("tshark process not started or already stopped")
	}
	return c.cmd.Process.Kill()
}

// Wait waits for the tshark command to finish.
func (c *Capture) Wait() error {
	if c.cmd == nil {
		return fmt.Errorf("tshark command not started")
	}
	return c.cmd.Wait()
}
