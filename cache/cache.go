package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// GetCacheDir returns the cache directory for GoShark based on the TShark version
func GetCacheDir(tsharkVersion string) (string, error) {
	var cacheDir string

	// Determine the cache directory based on the OS
	switch runtime.GOOS {
	case "windows":
		cacheDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "GoShark", tsharkVersion)
	case "darwin":
		cacheDir = filepath.Join(os.Getenv("HOME"), "Library", "Caches", "GoShark", tsharkVersion)
	case "linux":
		// Use XDG_CACHE_HOME if available, otherwise fallback to ~/.cache
		xdgCache := os.Getenv("XDG_CACHE_HOME")
		if xdgCache == "" {
			xdgCache = filepath.Join(os.Getenv("HOME"), ".cache")
		}
		cacheDir = filepath.Join(xdgCache, "goshark", tsharkVersion)
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Create the cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}

	return cacheDir, nil
}

// ClearCache removes the cache directory for the specified TShark version
// If tsharkVersion is empty, it clears all cache directories
func ClearCache(tsharkVersion string) error {
	var cacheDir string
	var err error

	if tsharkVersion == "" {
		// Clear all cache directories
		switch runtime.GOOS {
		case "windows":
			cacheDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "GoShark")
		case "darwin":
			cacheDir = filepath.Join(os.Getenv("HOME"), "Library", "Caches", "GoShark")
		case "linux":
			xdgCache := os.Getenv("XDG_CACHE_HOME")
			if xdgCache == "" {
				xdgCache = filepath.Join(os.Getenv("HOME"), ".cache")
			}
			cacheDir = filepath.Join(xdgCache, "goshark")
		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	} else {
		// Clear cache for specific TShark version
		cacheDir, err = GetCacheDir(tsharkVersion)
		if err != nil {
			return err
		}
	}

	// Check if the directory exists before removing it
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		// Directory doesn't exist, nothing to do
		return nil
	}

	// Remove the cache directory
	if err := os.RemoveAll(cacheDir); err != nil {
		return fmt.Errorf("failed to remove cache directory: %w", err)
	}

	return nil
}

// GetCachedFilePath returns the path to a cached file for the given key
func GetCachedFilePath(tsharkVersion, key string) (string, error) {
	cacheDir, err := GetCacheDir(tsharkVersion)
	if err != nil {
		return "", err
	}

	// Sanitize the key to make it a valid filename
	sanitizedKey := strings.ReplaceAll(key, "/", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, "\\", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, ":", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, "*", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, "?", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, "\"", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, "<", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, ">", "_")
	sanitizedKey = strings.ReplaceAll(sanitizedKey, "|", "_")

	return filepath.Join(cacheDir, sanitizedKey), nil
}
