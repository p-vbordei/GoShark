package capture

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCaptureOptions(t *testing.T) {
	// Test default options
	cap := NewCapture()
	assert.Equal(t, "", cap.OutputFile, "Default output file should be empty")
	assert.Equal(t, "", cap.DisplayFilter, "Default display filter should be empty")
	assert.Equal(t, "", cap.CaptureFilter, "Default capture filter should be empty")
	assert.True(t, cap.UseJSON, "Default UseJSON should be true")

	// Test with options
	cap = NewCapture(
		WithOutputFile("test.pcap"),
		WithDisplayFilter("tcp"),
	)

	assert.Equal(t, "test.pcap", cap.OutputFile, "Output file should be set")
	assert.Equal(t, "tcp", cap.DisplayFilter, "Display filter should be set")
}

func TestCaptureTSharkArgs(t *testing.T) {
	// Create a capture with options
	cap := NewCapture(
		WithOutputFile("test.pcap"),
		WithDisplayFilter("tcp"),
		WithTSharkPath("/usr/bin/tshark"),
	)

	args, err := cap.getTSharkArgs()
	assert.NoError(t, err)

	// Check that arguments include the expected options
	found := false
	for i, arg := range args {
		if arg == "-w" && i+1 < len(args) && args[i+1] == "test.pcap" {
			found = true
			break
		}
	}
	assert.True(t, found, "Arguments should include output file option")

	found = false
	for i, arg := range args {
		if arg == "-Y" && i+1 < len(args) && args[i+1] == "tcp" {
			found = true
			break
		}
	}
	assert.True(t, found, "Arguments should include display filter option")
}

func TestRemoteCaptureOptions(t *testing.T) {
	rc, err := NewRemoteCapture("192.168.1.100", "eth1", WithRemotePort(3333))
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.100", rc.RemoteHost)
	assert.Equal(t, "eth1", rc.RemoteInterface)
	assert.Equal(t, 3333, rc.RemotePort)
	assert.Equal(t, []string{"rpcap://192.168.1.100:3333/eth1"}, rc.Interfaces)

	// Verify Start reconstructs if interfaces are wiped out
	rc.Interfaces = nil
	_, _, err = rc.Start()
	// It's expected to error if tshark path isn't valid or interface doesn't exist, but reconstruction must occur.
	assert.Equal(t, []string{"rpcap://192.168.1.100:3333/eth1"}, rc.Interfaces)

	assert.Contains(t, rc.String(), "host=192.168.1.100")
	assert.Contains(t, rc.String(), "port=3333")
}

func TestLiveRingCaptureOptions(t *testing.T) {
	lrc, err := NewLiveRingCapture([]string{"eth0"}, WithRingFileSize(2048), WithNumRingFiles(5), WithRingFileName("/tmp/test.pcap"))
	assert.NoError(t, err)
	assert.Equal(t, 2048, lrc.RingFileSize)
	assert.Equal(t, 5, lrc.NumRingFiles)
	assert.Equal(t, "/tmp/test.pcap", lrc.RingFileName)
}

// containsPair reports whether args contains flag immediately followed by val.
func containsPair(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func TestLiveCaptureDumpcapParams(t *testing.T) {
	lc, err := NewLiveCapture([]string{"en0"}, WithBPFFilter("tcp"))
	assert.NoError(t, err)

	params := lc.getDumpcapParameters()
	assert.True(t, containsPair(params, "-f", "tcp"), "dumpcap params should include the BPF filter")
	assert.True(t, containsPair(params, "-i", "en0"), "dumpcap params should include the interface")
	assert.True(t, containsPair(params, "-w", "-"), "dumpcap should write to stdout")
}

func TestLiveRingTSharkArgs(t *testing.T) {
	lrc, err := NewLiveRingCapture([]string{"eth0"},
		WithRingFileSize(2048), WithNumRingFiles(5), WithRingFileName("/tmp/test.pcap"))
	assert.NoError(t, err)

	args, err := lrc.getRingTSharkArgs()
	assert.NoError(t, err)
	assert.True(t, containsPair(args, "-b", "filesize:2048"), "ring args should set the file size")
	assert.True(t, containsPair(args, "-b", "files:5"), "ring args should set the file count")
	assert.True(t, containsPair(args, "-w", "/tmp/test.pcap"), "ring args should set the output file")
	assert.True(t, containsPair(args, "-i", "eth0"), "ring args should include the interface")
}

func TestEKTSharkArgs(t *testing.T) {
	cap := NewCapture(WithUseEK(true))
	args, err := cap.getTSharkArgs()
	assert.NoError(t, err)
	assert.True(t, containsPair(args, "-T", "ek"), "UseEK should select -T ek")
}
