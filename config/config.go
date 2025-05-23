package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the application's configuration settings.
type Config struct {
	TSharkPath  string
	DumpcapPath string
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		TSharkPath:  findDefaultTSharkPath(),
		DumpcapPath: findDefaultDumpcapPath(),
	}
}

// LoadConfig loads configuration from a specified file.
func LoadConfig(configPath string) (*Config, error) {
	// Start with default config
	config := DefaultConfig()

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config file doesn't exist, use defaults
		return config, nil
	}

	// Load config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Decode JSON config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return config, nil
}

// SaveConfig saves the configuration to a file
func SaveConfig(config *Config, configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create or truncate config file
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	// Encode config as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// GetDefaultConfigPath returns the default path for the config file
func GetDefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "GoShark", "config.ini")
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "GoShark", "config.ini")
	case "linux":
		// Use XDG_CONFIG_HOME if available, otherwise fallback to ~/.config
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			xdgConfig = filepath.Join(os.Getenv("HOME"), ".config")
		}
		return filepath.Join(xdgConfig, "goshark", "config.ini")
	default:
		// Fallback to current directory
		return "config.ini"
	}
}

// findDefaultTSharkPath attempts to find the TShark executable in standard locations
func findDefaultTSharkPath() string {
	// Check if TSHARK_PATH environment variable is set
	if envPath := os.Getenv("TSHARK_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
	}

	// Standard locations based on OS
	var paths []string

	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		paths = []string{
			filepath.Join(programFiles, "Wireshark", "tshark.exe"),
			filepath.Join(programFilesX86, "Wireshark", "tshark.exe"),
		}
	case "darwin":
		paths = []string{
			"/usr/local/bin/tshark",
			"/usr/bin/tshark",
			"/opt/local/bin/tshark",
			"/opt/homebrew/bin/tshark",
		}
	case "linux":
		paths = []string{
			"/usr/bin/tshark",
			"/usr/sbin/tshark",
			"/usr/lib/tshark/tshark",
			"/usr/local/bin/tshark",
			"/bin/tshark",
		}
	}

	// Check each path
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// If no path is found, return just the executable name and rely on PATH
	if runtime.GOOS == "windows" {
		return "tshark.exe"
	}
	return "tshark"
}

// findDefaultDumpcapPath attempts to find the Dumpcap executable in standard locations
func findDefaultDumpcapPath() string {
	// Check if DUMPCAP_PATH environment variable is set
	if envPath := os.Getenv("DUMPCAP_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
	}

	// Try to find dumpcap in the same directory as tshark
	tsharkPath := findDefaultTSharkPath()
	if tsharkPath != "tshark" && tsharkPath != "tshark.exe" {
		dumpcapPath := filepath.Join(filepath.Dir(tsharkPath), "dumpcap")
		if runtime.GOOS == "windows" {
			dumpcapPath += ".exe"
		}
		if _, err := os.Stat(dumpcapPath); err == nil {
			return dumpcapPath
		}
	}

	// Standard locations based on OS
	var paths []string

	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		paths = []string{
			filepath.Join(programFiles, "Wireshark", "dumpcap.exe"),
			filepath.Join(programFilesX86, "Wireshark", "dumpcap.exe"),
		}
	case "darwin":
		paths = []string{
			"/usr/local/bin/dumpcap",
			"/usr/bin/dumpcap",
			"/opt/local/bin/dumpcap",
			"/opt/homebrew/bin/dumpcap",
		}
	case "linux":
		paths = []string{
			"/usr/bin/dumpcap",
			"/usr/sbin/dumpcap",
			"/usr/lib/dumpcap/dumpcap",
			"/usr/local/bin/dumpcap",
			"/bin/dumpcap",
		}
	}

	// Check each path
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// If no path is found, return just the executable name and rely on PATH
	if runtime.GOOS == "windows" {
		return "dumpcap.exe"
	}
	return "dumpcap"
}
