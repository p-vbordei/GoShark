package capture

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strconv"

	"GoShark/packet"
	"GoShark/packet/layers"
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
	Snaplen       int
	Promiscuous   bool
	MonitorMode   bool
	OutputFile    string
	UseEK         bool // Use tshark's Elastic Common Schema (-T ek) output.
	KeepPackets   bool // Retain packets passed through LoadPackets (pyshark keep_packets).
	additionalArgs []string

	packets []*packet.Packet // Buffer populated by LoadPackets.
	debug   bool             // When true, tshark stderr is logged.

	cmd *exec.Cmd
}

// Option is a functional option for configuring captures.
type Option func(interface{})

// getCapture extracts the base Capture struct pointer from any capture type.
func getCapture(v interface{}) *Capture {
	if c, ok := v.(*Capture); ok {
		return c
	}
	switch cap := v.(type) {
	case *FileCapture:
		return &cap.Capture
	case *LiveCapture:
		return cap.Capture
	case *RemoteCapture:
		if cap.LiveCapture != nil {
			return cap.LiveCapture.Capture
		}
	case *LiveRingCapture:
		if cap.LiveCapture != nil {
			return cap.LiveCapture.Capture
		}
	case *InMemCapture:
		return &cap.Capture
	}
	return nil
}

// NewCapture creates a new base Capture object.
func NewCapture(options ...Option) *Capture {
	c := &Capture{
		UseJSON:     true, // Default to JSON output for easier parsing
		KeepPackets: true, // Match pyshark's keep_packets=True default
	}

	for _, option := range options {
		option(c)
	}
	return c
}

// WithDisplayFilter sets the Wireshark display filter for the capture (e.g., "http.request").
// Corresponds to tshark's -Y flag.
func WithDisplayFilter(filter string) Option { 
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.DisplayFilter = filter
		}
	}
}

// WithCaptureFilter sets the BPF capture filter for the capture (e.g., "tcp port 80").
// Corresponds to tshark's -f flag.
func WithCaptureFilter(filter string) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.CaptureFilter = filter
		}
	}
}

// WithTSharkPath sets the absolute path to the tshark executable.
func WithTSharkPath(path string) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.TSharkPath = path
		}
	}
}

// WithUseJSON sets whether to use JSON output from tshark. If false, PDML is used.
// Corresponds to tshark's -T json or -T pdml flags.
func WithUseJSON(useJSON bool) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.UseJSON = useJSON
		}
	}
}

// WithUseEK selects tshark's Elastic Common Schema output (-T ek). It takes
// precedence over WithUseJSON. Corresponds to pyshark's use_ek.
func WithUseEK(useEK bool) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.UseEK = useEK
		}
	}
}

// WithKeepPackets controls whether LoadPackets retains packets in memory for
// later indexed access. Corresponds to pyshark's keep_packets (default true).
func WithKeepPackets(keep bool) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.KeepPackets = keep
		}
	}
}

// WithIncludeRaw sets whether to include raw packet data in the output. (Note: tshark JSON often includes raw data by default).
func WithIncludeRaw(includeRaw bool) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.IncludeRaw = includeRaw
		}
	}
}

// WithDecodes adds decode-as rules (e.g., "tcp.port==8888,http").
// Corresponds to tshark's -d flag.
func WithDecodes(decodes ...string) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.Decodes = append(c.Decodes, decodes...)
		}
	}
}

// WithEncryptionKeys adds WEP/WPA/WPA2 encryption keys (e.g., "wpa-pwd:password:ssid").
// Corresponds to tshark's -o wlan.wep_keys flag.
func WithEncryptionKeys(keys ...string) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.EncryptionKeys = append(c.EncryptionKeys, keys...)
		}
	}
}

// WithOverridePreferences adds override preferences (e.g., "tcp.port:80").
// Corresponds to tshark's -o flag.
func WithOverridePreferences(prefs ...string) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.OverridePreferences = append(c.OverridePreferences, prefs...)
		}
	}
}

// WithPacketCount sets the maximum number of packets to capture. 0 means unlimited.
// Corresponds to tshark's -c flag.
func WithPacketCount(count int) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.PacketCount = count
		}
	}
}

// WithSnaplen sets the maximum number of bytes to capture per packet. 0 means unlimited.
// Corresponds to tshark's -s flag.
func WithSnaplen(snaplen int) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.Snaplen = snaplen
		}
	}
}

// WithPromiscuous sets whether to capture in promiscuous mode. True by default in tshark.
// Corresponds to tshark's -p flag (disables promiscuous mode if -p is present).
func WithPromiscuous(promiscuous bool) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.Promiscuous = promiscuous
		}
	}
}

// WithMonitorMode sets whether to capture in monitor mode. Applicable to wireless interfaces.
// Corresponds to tshark's -I flag.
func WithMonitorMode(monitorMode bool) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.MonitorMode = monitorMode
		}
	}
}

// WithOutputFile sets the output file for the capture.
// Corresponds to tshark's -w flag.
func WithOutputFile(outputFile string) Option {
	return func(v interface{}) {
		if c := getCapture(v); c != nil {
			c.OutputFile = outputFile
		}
	}
}

// SetCommandLineArgs sets additional command line arguments for tshark.
func (c *Capture) SetCommandLineArgs(args ...string) {
	c.additionalArgs = args
}

// getTSharkArgs constructs the tshark command arguments based on the Capture configuration.
func (c *Capture) getTSharkArgs() ([]string, error) {
	args := []string{"-l", "-n"}

	// Add any additional arguments
	if len(c.additionalArgs) > 0 {
		args = append(args, c.additionalArgs...)
	}

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

	// If an output file is specified, add the -w flag
	if c.OutputFile != "" {
		args = append(args, "-w", c.OutputFile)
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

	return c.startWithArgs(args)
}

// startWithArgs starts the tshark capture process with the given arguments.
// It returns readers for stdout and stderr.
func (c *Capture) startWithArgs(args []string) (io.ReadCloser, io.ReadCloser, error) {
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

// Stop stops the tshark capture process. It is a no-op (no error) if the
// process was never started, so Close is always safe to call.
func (c *Capture) Stop() error {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	return c.cmd.Process.Kill()
}

// Close stops the capture, releasing the tshark process. pyshark's close().
func (c *Capture) Close() error {
	return c.Stop()
}

// SetDebug toggles logging of tshark's stderr to the standard logger.
func (c *Capture) SetDebug(on bool) {
	c.debug = on
}

// LoadPackets eagerly captures up to count packets (count <= 0 means all) and,
// when KeepPackets is set, buffers them for indexed access via Get/Len/Packets.
// startFunc launches the underlying tshark process (each capture type provides
// its own); the concrete capture types expose a no-argument LoadPackets wrapper.
func (c *Capture) LoadPackets(ctx context.Context, count int,
	startFunc func() (io.ReadCloser, io.ReadCloser, error)) ([]*packet.Packet, error) {
	c.packets = nil
	n := 0
	err := c.ApplyOnPackets(func(p *packet.Packet) bool {
		if c.KeepPackets {
			c.packets = append(c.packets, p)
		}
		n++
		return count > 0 && n >= count
	}, ctx, startFunc)
	return c.packets, err
}

// Len returns the number of buffered packets (after LoadPackets).
func (c *Capture) Len() int {
	return len(c.packets)
}

// Get returns the i-th buffered packet, or nil if the index is out of range.
func (c *Capture) Get(i int) *packet.Packet {
	if i < 0 || i >= len(c.packets) {
		return nil
	}
	return c.packets[i]
}

// Packets returns all buffered packets (after LoadPackets).
func (c *Capture) Packets() []*packet.Packet {
	return c.packets
}

// Wait waits for the tshark command to finish.
func (c *Capture) Wait() error {
	if c.cmd == nil {
		return fmt.Errorf("tshark command not started")
	}
	return c.cmd.Wait()
}

// sniffStream reads packets from stdout in a streaming fashion.
func (c *Capture) sniffStream(ctx context.Context, stdout io.ReadCloser, stderr io.ReadCloser) (<-chan *packet.Packet, error) {
	outChan := make(chan *packet.Packet, 100)
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			stdout.Close()
			stderr.Close()
		case <-done:
		}
	}()

	go func() {
		defer stdout.Close()
		defer stderr.Close()
		defer close(outChan)
		defer close(done)

		if c.UseJSON {
			decoder := json.NewDecoder(stdout)
			// Read the first token which must be '['
			t, err := decoder.Token()
			if err != nil {
				return
			}
			delim, ok := t.(json.Delim)
			if !ok || delim != '[' {
				return
			}

			// Read each packet object as it becomes available
			for decoder.More() {
				// Check for context cancellation
				select {
				case <-ctx.Done():
					return
				default:
				}

				var pkt packet.Packet
				if err := decoder.Decode(&pkt); err != nil {
					return
				}
				// Populate JSON layers
				for i := range pkt.Layers {
					pkt.Layers[i].JSONLayer = layers.NewJSONLayer(pkt.Layers[i].Name, pkt.Layers[i].Fields, pkt.Layers[i].Name, false)
				}

				select {
				case <-ctx.Done():
					return
				case outChan <- &pkt:
				}
			}
		} else {
			// XML / PDML stream parsing
			decoder := xml.NewDecoder(stdout)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				t, err := decoder.Token()
				if err != nil {
					return
				}

				if se, ok := t.(xml.StartElement); ok && se.Name.Local == "packet" {
					var pdmlPacket tshark.PDMLPacket
					if err := decoder.DecodeElement(&pdmlPacket, &se); err != nil {
						return
					}

					// Convert PDMLPacket to packet.Packet using XMLParser's logic
					parser := tshark.NewXMLParser(tshark.WithXMLIncludeRaw(c.IncludeRaw))
					pkt, err := parser.ConvertPDMLPacket(&pdmlPacket)
					if err == nil {
						select {
						case <-ctx.Done():
							return
						case outChan <- pkt:
						}
					}
				}
			}
		}
	}()

	return outChan, nil
}

// ApplyOnPackets applies the callback to all captured packets.
// If the callback returns true, sniffing is stopped early.
func (c *Capture) ApplyOnPackets(callback func(*packet.Packet) bool, ctx context.Context, startFunc func() (io.ReadCloser, io.ReadCloser, error)) error {
	stdout, stderr, err := startFunc()
	if err != nil {
		return err
	}

	packets, err := c.sniffStream(ctx, stdout, stderr)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			c.Stop()
			return ctx.Err()
		case pkt, ok := <-packets:
			if !ok {
				return nil
			}
			if callback(pkt) {
				c.Stop()
				return nil
			}
		}
	}
}
