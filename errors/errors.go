package errors

import (
	"errors"
	"fmt"
)

// BaseError provides common functionality for all error types
type BaseError struct {
	message string
	cause   error
}

// Error implements the error interface
func (e *BaseError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.message, e.cause)
	}
	return e.message
}

// Unwrap returns the cause of the error
func (e *BaseError) Unwrap() error {
	return e.cause
}

// Message returns the error message
func (e *BaseError) Message() string {
	return e.message
}

// Cause returns the underlying cause of the error
func (e *BaseError) Cause() error {
	return e.cause
}

// TSharkError represents an error related to TShark execution
type TSharkError struct {
	BaseError
	command string
	output  string
}

// NewTSharkError creates a new TSharkError
func NewTSharkError(message string, command string, output string, cause error) *TSharkError {
	return &TSharkError{
		BaseError: BaseError{
			message: message,
			cause:   cause,
		},
		command: command,
		output:  output,
	}
}

// Command returns the command that caused the error
func (e *TSharkError) Command() string {
	return e.command
}

// Output returns the command output
func (e *TSharkError) Output() string {
	return e.output
}

// TSharkNotFoundError represents an error when TShark executable is not found
type TSharkNotFoundError struct {
	BaseError
	path string
}

// NewTSharkNotFoundError creates a new TSharkNotFoundError
func NewTSharkNotFoundError(path string) *TSharkNotFoundError {
	return &TSharkNotFoundError{
		BaseError: BaseError{
			message: "TShark executable not found",
		},
		path: path,
	}
}

// Path returns the path that was searched
func (e *TSharkNotFoundError) Path() string {
	return e.path
}

// ParseError represents an error during packet parsing
type ParseError struct {
	BaseError
	format string
}

// NewParseError creates a new ParseError
func NewParseError(message string, format string, cause error) *ParseError {
	return &ParseError{
		BaseError: BaseError{
			message: message,
			cause:   cause,
		},
		format: format,
	}
}

// Format returns the format that caused the error
func (e *ParseError) Format() string {
	return e.format
}

// JSONParseError represents an error during JSON parsing
type JSONParseError struct {
	ParseError
}

// NewJSONParseError creates a new JSONParseError
func NewJSONParseError(message string, cause error) *JSONParseError {
	return &JSONParseError{
		ParseError: *NewParseError(message, "JSON", cause),
	}
}

// XMLParseError represents an error during XML parsing
type XMLParseError struct {
	ParseError
}

// NewXMLParseError creates a new XMLParseError
func NewXMLParseError(message string, cause error) *XMLParseError {
	return &XMLParseError{
		ParseError: *NewParseError(message, "XML", cause),
	}
}

// EKParseError represents an error during EK parsing
type EKParseError struct {
	ParseError
}

// NewEKParseError creates a new EKParseError
func NewEKParseError(message string, cause error) *EKParseError {
	return &EKParseError{
		ParseError: *NewParseError(message, "EK", cause),
	}
}

// CaptureError represents an error during packet capture
type CaptureError struct {
	BaseError
	iface string
}

// NewCaptureError creates a new CaptureError
func NewCaptureError(message string, iface string, cause error) *CaptureError {
	return &CaptureError{
		BaseError: BaseError{
			message: message,
			cause:   cause,
		},
		iface: iface,
	}
}

// Interface returns the interface that caused the error
func (e *CaptureError) Interface() string {
	return e.iface
}

// InvalidInterfaceError represents an error when an invalid interface is specified
type InvalidInterfaceError struct {
	CaptureError
}

// NewInvalidInterfaceError creates a new InvalidInterfaceError
func NewInvalidInterfaceError(iface string) *InvalidInterfaceError {
	return &InvalidInterfaceError{
		CaptureError: *NewCaptureError(fmt.Sprintf("Invalid interface: %s", iface), iface, nil),
	}
}

// FileNotFoundError represents an error when a capture file is not found
type FileNotFoundError struct {
	BaseError
	filePath string
}

// NewFileNotFoundError creates a new FileNotFoundError
func NewFileNotFoundError(filePath string) *FileNotFoundError {
	return &FileNotFoundError{
		BaseError: BaseError{
			message: fmt.Sprintf("File not found: %s", filePath),
		},
		filePath: filePath,
	}
}

// FilePath returns the file path that was not found
func (e *FileNotFoundError) FilePath() string {
	return e.filePath
}

// InvalidFilterError represents an error when an invalid filter is specified
type InvalidFilterError struct {
	BaseError
	filter string
}

// NewInvalidFilterError creates a new InvalidFilterError
func NewInvalidFilterError(filter string, cause error) *InvalidFilterError {
	return &InvalidFilterError{
		BaseError: BaseError{
			message: fmt.Sprintf("Invalid filter: %s", filter),
			cause:   cause,
		},
		filter: filter,
	}
}

// Filter returns the filter that caused the error
func (e *InvalidFilterError) Filter() string {
	return e.filter
}

// As attempts to convert an error to a specific type
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Is reports whether any error in err's chain matches target
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// Wrap wraps an error with a message
func Wrap(err error, message string) error {
	return fmt.Errorf("%s: %w", message, err)
}

// Unwrap returns the result of calling the Unwrap method on err, if err's
// type contains an Unwrap method returning error.
// Otherwise, Unwrap returns nil.
func Unwrap(err error) error {
	u, ok := err.(interface {
		Unwrap() error
	})
	if !ok {
		return nil
	}
	return u.Unwrap()
}
