package utils

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(dirname string) bool {
	info, err := os.Stat(dirname)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// CreateDirIfNotExist creates a directory if it doesn't exist
func CreateDirIfNotExist(dirname string) error {
	if !DirExists(dirname) {
		return os.MkdirAll(dirname, os.ModePerm)
	}
	return nil
}

// GetExecutablePath returns the path of the executable
func GetExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// IsCommandAvailable checks if a command is available in the system PATH
func IsCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ParseInt parses a string to an integer with a default value if parsing fails
func ParseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}

	i, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}

	return i
}

// ParseFloat parses a string to a float with a default value if parsing fails
func ParseFloat(s string, defaultValue float64) float64 {
	if s == "" {
		return defaultValue
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultValue
	}

	return f
}

// ParseBool parses a string to a boolean with a default value if parsing fails
func ParseBool(s string, defaultValue bool) bool {
	if s == "" {
		return defaultValue
	}

	b, err := strconv.ParseBool(s)
	if err != nil {
		return defaultValue
	}

	return b
}

// ParseTime parses a string to a time.Time with a default value if parsing fails
func ParseTime(s string, layout string, defaultValue time.Time) time.Time {
	if s == "" {
		return defaultValue
	}

	t, err := time.Parse(layout, s)
	if err != nil {
		return defaultValue
	}

	return t
}

// ParseTimeEpoch parses a string containing an epoch time (seconds since 1970)
func ParseTimeEpoch(s string, defaultValue time.Time) time.Time {
	if s == "" {
		return defaultValue
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultValue
	}

	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)

	return time.Unix(sec, nsec)
}

// IsValidIPAddress checks if a string is a valid IP address
func IsValidIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidMACAddress checks if a string is a valid MAC address
func IsValidMACAddress(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

// IsValidPort checks if a port number is valid (1-65535)
func IsValidPort(port int) bool {
	return port > 0 && port < 65536
}

// GetOSType returns the operating system type
func GetOSType() string {
	return runtime.GOOS
}

// IsWindows returns true if the operating system is Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsLinux returns true if the operating system is Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsMacOS returns true if the operating system is macOS
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// ReadLines reads a file and returns its lines as a slice of strings
func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

// WriteLines writes a slice of strings to a file, one line per string
func WriteLines(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}

	return writer.Flush()
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filename string) (int64, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return 0, err
	}

	return info.Size(), nil
}

// GetFileExtension returns the extension of a file
func GetFileExtension(filename string) string {
	return filepath.Ext(filename)
}

// JoinPaths joins multiple path components into a single path
func JoinPaths(paths ...string) string {
	return filepath.Join(paths...)
}

// GetAbsolutePath returns the absolute path of a file
func GetAbsolutePath(path string) (string, error) {
	return filepath.Abs(path)
}

// FormatBytes formats a byte count as a human-readable string (e.g., "2.5 MB")
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats a duration as a human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}

	s := d.Seconds()
	if s < 60 {
		return fmt.Sprintf("%.1f s", s)
	}

	m := d.Minutes()
	if m < 60 {
		return fmt.Sprintf("%.1f m", m)
	}

	h := d.Hours()
	if h < 24 {
		return fmt.Sprintf("%.1f h", h)
	}

	return fmt.Sprintf("%.1f d", h/24)
}

// SplitCommandLine splits a command line string into arguments, respecting quotes
func SplitCommandLine(cmdline string) []string {
	var args []string
	state := "start"
	current := ""
	quote := ""
	escapeNext := false

	for i := 0; i < len(cmdline); i++ {
		c := cmdline[i]

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if quote != "" {
			if string(c) == quote {
				quote = ""
			} else {
				current += string(c)
			}
			continue
		}

		if c == '"' || c == '\'' {
			quote = string(c)
			continue
		}

		if c == ' ' || c == '\t' {
			if state == "arg" {
				args = append(args, current)
				current = ""
			}
			state = "start"
			continue
		}

		current += string(c)
		state = "arg"
	}

	if state == "arg" {
		args = append(args, current)
	}

	return args
}

// IsNumeric checks if a string contains only numeric characters
func IsNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// IsHexadecimal checks if a string contains only hexadecimal characters
func IsHexadecimal(s string) bool {
	s = strings.ToLower(s)
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

// HexToBytes converts a hexadecimal string to a byte slice
func HexToBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")

	if len(s)%2 != 0 {
		s = "0" + s
	}

	return hex.DecodeString(s)
}

// BytesToHex converts a byte slice to a hexadecimal string
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// BytesToHexFormatted converts a byte slice to a formatted hexadecimal string with spaces
func BytesToHexFormatted(b []byte, separator string) string {
	hexStr := hex.EncodeToString(b)
	var formatted strings.Builder

	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			formatted.WriteString(separator)
		}
		formatted.WriteString(hexStr[i : i+2])
	}

	return formatted.String()
}
