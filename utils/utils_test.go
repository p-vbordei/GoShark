package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileAndDirHelpers(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "goshark_utils_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// DirExists
	assert.True(t, DirExists(tempDir))
	assert.False(t, DirExists(filepath.Join(tempDir, "nonexistent")))

	// FileExists on dir should be false
	assert.False(t, FileExists(tempDir))

	// Create a temp file
	tempFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(tempFile, []byte("hello"), 0644)
	assert.NoError(t, err)

	// FileExists on file should be true
	assert.True(t, FileExists(tempFile))
	assert.False(t, FileExists(filepath.Join(tempDir, "nonexistent.txt")))

	// CreateDirIfNotExist
	newDir := filepath.Join(tempDir, "new_sub_dir")
	assert.False(t, DirExists(newDir))
	err = CreateDirIfNotExist(newDir)
	assert.NoError(t, err)
	assert.True(t, DirExists(newDir))

	// GetExecutablePath
	exeDir, err := GetExecutablePath()
	assert.NoError(t, err)
	assert.NotEmpty(t, exeDir)

	// IsCommandAvailable
	assert.True(t, IsCommandAvailable("go"))
	assert.False(t, IsCommandAvailable("nonexistent-command-xyz"))
}

func TestParsingHelpers(t *testing.T) {
	// ParseInt
	assert.Equal(t, 123, ParseInt("123", 10))
	assert.Equal(t, 10, ParseInt("invalid", 10))
	assert.Equal(t, 10, ParseInt("", 10))

	// ParseFloat
	assert.Equal(t, 1.23, ParseFloat("1.23", 10.0))
	assert.Equal(t, 10.0, ParseFloat("invalid", 10.0))
	assert.Equal(t, 10.0, ParseFloat("", 10.0))

	// ParseBool
	assert.True(t, ParseBool("true", false))
	assert.True(t, ParseBool("1", false))
	assert.False(t, ParseBool("false", true))
	assert.False(t, ParseBool("0", true))
	assert.True(t, ParseBool("invalid", true))
	assert.True(t, ParseBool("", true))

	// ParseTime
	now := time.Now()
	parsedTime := ParseTime("2026-05-22T09:17:19Z", time.RFC3339, now)
	assert.Equal(t, 2026, parsedTime.Year())
	assert.Equal(t, time.Month(5), parsedTime.Month())
	assert.Equal(t, 22, parsedTime.Day())

	invalidTime := ParseTime("invalid", time.RFC3339, now)
	assert.Equal(t, now, invalidTime)
	assert.Equal(t, now, ParseTime("", time.RFC3339, now))

	// ParseTimeEpoch
	epochTime := ParseTimeEpoch("1684747039.5", now)
	assert.Equal(t, int64(1684747039), epochTime.Unix())
	assert.Equal(t, int64(1684747039), epochTime.Unix())
	assert.Equal(t, now, ParseTimeEpoch("invalid", now))
	assert.Equal(t, now, ParseTimeEpoch("", now))
}

func TestNetworkValidators(t *testing.T) {
	// IsValidIPAddress
	assert.True(t, IsValidIPAddress("192.168.1.1"))
	assert.True(t, IsValidIPAddress("2001:db8::68"))
	assert.False(t, IsValidIPAddress("invalid-ip"))

	// IsValidMACAddress
	assert.True(t, IsValidMACAddress("00:11:22:33:44:55"))
	assert.True(t, IsValidMACAddress("00-11-22-33-44-55"))
	assert.False(t, IsValidMACAddress("invalid-mac"))

	// IsValidPort
	assert.True(t, IsValidPort(80))
	assert.True(t, IsValidPort(65535))
	assert.False(t, IsValidPort(0))
	assert.False(t, IsValidPort(-1))
	assert.False(t, IsValidPort(65536))
}

func TestOSTypeHelpers(t *testing.T) {
	osType := GetOSType()
	assert.NotEmpty(t, osType)

	assert.Equal(t, runtime.GOOS == "windows", IsWindows())
	assert.Equal(t, runtime.GOOS == "linux", IsLinux())
	assert.Equal(t, runtime.GOOS == "darwin", IsMacOS())
}

func TestFileIOHelpers(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "goshark_utils_io_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tempFile := filepath.Join(tempDir, "test.txt")
	lines := []string{"line1", "line2", "line3"}

	// WriteLines
	err = WriteLines(tempFile, lines)
	assert.NoError(t, err)

	// ReadLines
	readLines, err := ReadLines(tempFile)
	assert.NoError(t, err)
	assert.Equal(t, lines, readLines)

	// ReadLines for nonexistent file
	_, err = ReadLines(filepath.Join(tempDir, "nonexistent.txt"))
	assert.Error(t, err)

	// GetFileSize
	sz, err := GetFileSize(tempFile)
	assert.NoError(t, err)
	assert.True(t, sz > 0)

	// GetFileExtension
	assert.Equal(t, ".txt", GetFileExtension(tempFile))

	// CopyFile
	copyFile := filepath.Join(tempDir, "test_copy.txt")
	err = CopyFile(tempFile, copyFile)
	assert.NoError(t, err)
	assert.True(t, FileExists(copyFile))
	copySz, _ := GetFileSize(copyFile)
	assert.Equal(t, sz, copySz)

	// JoinPaths
	assert.Equal(t, filepath.Join("a", "b", "c"), JoinPaths("a", "b", "c"))

	// GetAbsolutePath
	abs, err := GetAbsolutePath(tempFile)
	assert.NoError(t, err)
	assert.True(t, filepath.IsAbs(abs))
}

func TestFormatHelpers(t *testing.T) {
	// FormatBytes
	assert.Equal(t, "500 B", FormatBytes(500))
	assert.Equal(t, "1.0 KB", FormatBytes(1024))
	assert.Equal(t, "1.5 KB", FormatBytes(1536))
	assert.Equal(t, "2.0 MB", FormatBytes(2*1024*1024))

	// FormatDuration
	assert.Equal(t, "500 ms", FormatDuration(500*time.Millisecond))
	assert.Equal(t, "5.0 s", FormatDuration(5*time.Second))
	assert.Equal(t, "2.5 m", FormatDuration(150*time.Second))
	assert.Equal(t, "2.0 h", FormatDuration(120*time.Minute))
	assert.Equal(t, "2.0 d", FormatDuration(48*time.Hour))
}

func TestSplitCommandLine(t *testing.T) {
	tests := []struct {
		cmdline string
		expected []string
	}{
		{"tshark -r file.pcap", []string{"tshark", "-r", "file.pcap"}},
		{"tshark -Y \"http.request or dns\"", []string{"tshark", "-Y", "http.request or dns"}},
		{"tshark -Y 'http.request or dns'", []string{"tshark", "-Y", "http.request or dns"}},
		{"echo \\\"hello\\\"", []string{"echo", "\"hello\""}},
		{"  spaces   everywhere  ", []string{"spaces", "everywhere"}},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.expected, SplitCommandLine(tc.cmdline))
	}
}

func TestHexHelpers(t *testing.T) {
	// IsNumeric
	assert.True(t, IsNumeric("12345"))
	assert.False(t, IsNumeric("123a5"))
	assert.False(t, IsNumeric(""))

	// IsHexadecimal
	assert.True(t, IsHexadecimal("1a2b3c"))
	assert.True(t, IsHexadecimal("1A2B3C"))
	assert.False(t, IsHexadecimal("1a2b3g"))
	assert.False(t, IsHexadecimal(""))

	// HexToBytes / BytesToHex
	bytes, err := HexToBytes("1a2b3c")
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x1a, 0x2b, 0x3c}, bytes)

	bytesOdd, err := HexToBytes("1a2b3")
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0xa2, 0xb3}, bytesOdd)

	hexStr := BytesToHex([]byte{0x1a, 0x2b, 0x3c})
	assert.Equal(t, "1a2b3c", hexStr)

	// BytesToHexFormatted
	formatted := BytesToHexFormatted([]byte{0x1a, 0x2b, 0x3c}, ":")
	assert.Equal(t, "1a:2b:3c", formatted)
}
