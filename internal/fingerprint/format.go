// Package fingerprint provides utilities for validating fingerprint formats.
package fingerprint

import "strings"

// IsValid checks if a fingerprint is in the correct format (uppercase with colons).
//
// The function validates that:
//   - All characters (except colons) are uppercase hexadecimal (0-9, A-F)
//   - Each byte is represented by exactly 2 characters
//   - Bytes are separated by colons
//
// Example:
//
//	valid := fingerprint.IsValid("AA:BB:CC:DD:EE:FF")
//	if !valid {
//	    log.Fatal("Invalid fingerprint format")
//	}
func IsValid(fp string) bool {
	cleaned := strings.ReplaceAll(fp, ":", "")

	// Check all characters are hex and uppercase
	for _, c := range cleaned {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}

	// Check colons are in the right places (each part must be exactly 2 characters)
	parts := strings.SplitSeq(fp, ":")
	for part := range parts {
		if len(part) != 2 {
			return false
		}
	}

	return true
}
