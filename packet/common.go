package packet

import (
	"fmt"
	"strings"
)

// ColorCode represents ANSI color codes for terminal output
type ColorCode struct {
	Code      string
	BoldCode  string
	ResetCode string
}

// Color codes for terminal output
var (
	ColorRed     = ColorCode{"\033[31m", "\033[1;31m", "\033[0m"}
	ColorGreen   = ColorCode{"\033[32m", "\033[1;32m", "\033[0m"}
	ColorYellow  = ColorCode{"\033[33m", "\033[1;33m", "\033[0m"}
	ColorBlue    = ColorCode{"\033[34m", "\033[1;34m", "\033[0m"}
	ColorMagenta = ColorCode{"\033[35m", "\033[1;35m", "\033[0m"}
	ColorCyan    = ColorCode{"\033[36m", "\033[1;36m", "\033[0m"}
	ColorWhite   = ColorCode{"\033[37m", "\033[1;37m", "\033[0m"}
)

// ColorMap maps color names to their ANSI codes
var ColorMap = map[string]ColorCode{
	"red":     ColorRed,
	"green":   ColorGreen,
	"yellow":  ColorYellow,
	"blue":    ColorBlue,
	"magenta": ColorMagenta,
	"cyan":    ColorCyan,
	"white":   ColorWhite,
}

// Colored returns a string with ANSI color codes for terminal output
func Colored(text string, color string, bold bool) string {
	colorCode, ok := ColorMap[strings.ToLower(color)]
	if !ok {
		return text
	}

	if bold {
		return fmt.Sprintf("%s%s%s", colorCode.BoldCode, text, colorCode.ResetCode)
	}
	return fmt.Sprintf("%s%s%s", colorCode.Code, text, colorCode.ResetCode)
}

// SanitizeFieldName sanitizes a field name by replacing dots and dashes with underscores
func SanitizeFieldName(fieldName string, prefix string) string {
	// Remove the prefix if it exists
	fieldName = strings.TrimPrefix(fieldName, prefix)
	// Replace dots and dashes with underscores
	return strings.ReplaceAll(strings.ReplaceAll(fieldName, ".", "_"), "-", "_")
}

// GetFieldPrefix returns the field prefix for a layer
func GetFieldPrefix(layerName string) string {
	if layerName == "geninfo" {
		return ""
	}
	return layerName + "."
}
