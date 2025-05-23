package tshark

import (
	"fmt"
	"os/exec"
	"strings"
)

// FilterType represents the type of filter to apply
type FilterType string

const (
	// DisplayFilter is a Wireshark display filter (post-capture)
	DisplayFilter FilterType = "display"
	// CaptureFilter is a BPF capture filter (during capture)
	CaptureFilter FilterType = "capture"
)

// Filter represents a packet filter for TShark
type Filter struct {
	Type  FilterType
	Value string
}

// NewDisplayFilter creates a new display filter
func NewDisplayFilter(value string) *Filter {
	return &Filter{
		Type:  DisplayFilter,
		Value: value,
	}
}

// NewCaptureFilter creates a new capture filter
func NewCaptureFilter(value string) *Filter {
	return &Filter{
		Type:  CaptureFilter,
		Value: value,
	}
}

// Validate checks if a filter is valid using TShark
func (f *Filter) Validate() error {
	if f.Value == "" {
		return nil // Empty filter is valid
	}

	args := []string{}

	switch f.Type {
	case DisplayFilter:
		args = append(args, "-Y", f.Value, "-c", "1")
	case CaptureFilter:
		args = append(args, "-f", f.Value, "-c", "1")
	default:
		return fmt.Errorf("invalid filter: %s (unknown filter type: %s)", f.Value, f.Type)
	}

	// Add a dummy interface or file to capture from
	args = append(args, "-i", "1")

	// Run TShark with the filter to validate
	tsharkPath, err := FindTShark()
	if err != nil {
		return err
	}
	// Create the command
	cmd := exec.Command(tsharkPath, args...)
	cmd.Stderr = nil
	cmd.Stdout = nil

	runErr := cmd.Run()
	if runErr != nil {
		return fmt.Errorf("invalid filter: %s (%w)", f.Value, runErr)
	}

	return nil
}

// AddFilterToArgs adds the filter to TShark command arguments
func AddFilterToArgs(args []string, filters ...*Filter) ([]string, error) {
	if len(filters) == 0 {
		return args, nil
	}

	// Group filters by type
	displayFilters := []string{}
	captureFilters := []string{}

	for _, filter := range filters {
		if filter == nil || filter.Value == "" {
			continue
		}

		switch filter.Type {
		case DisplayFilter:
			displayFilters = append(displayFilters, filter.Value)
		case CaptureFilter:
			captureFilters = append(captureFilters, filter.Value)
		default:
			return args, fmt.Errorf("invalid filter: %s (unknown filter type: %s)", filter.Value, filter.Type)
		}
	}

	// Add display filters (combined with AND)
	if len(displayFilters) > 0 {
		combinedFilter := strings.Join(displayFilters, ") and (")
		if len(displayFilters) > 1 {
			combinedFilter = "(" + combinedFilter + ")"
		}
		args = append(args, "-Y", combinedFilter)
	}

	// Add capture filters (combined with AND)
	if len(captureFilters) > 0 {
		combinedFilter := strings.Join(captureFilters, ") and (")
		if len(captureFilters) > 1 {
			combinedFilter = "(" + combinedFilter + ")"
		}
		args = append(args, "-f", combinedFilter)
	}

	return args, nil
}

// BuildTSharkFilterArgs builds TShark command arguments with the given filters
func BuildTSharkFilterArgs(baseArgs []string, filters ...*Filter) ([]string, error) {
	return AddFilterToArgs(baseArgs, filters...)
}
