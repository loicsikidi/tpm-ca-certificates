package utils

import (
	"fmt"
	"io"
	"os"
)

const (
	// DefaultMaxFileSize is the default maximum file size for [ReadFileSecure] (5 MiB).
	DefaultMaxFileSize int64 = 5 * 1024 * 1024
)

// FileExists checks if a file exists and is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists.
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// ReadFile reads the content of a file with a maximum size limit.
//
// Default maximum size is [DefaultMaxFileSize], but can be overridden by providing a custom maxSize in bytes.
func ReadFile(filename string, maxSize ...int64) ([]byte, error) {
	max := DefaultMaxFileSize
	if len(maxSize) > 0 {
		max = maxSize[0]
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limitedReader := io.LimitReader(file, max+1)

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > max {
		return nil, fmt.Errorf("file too large: exceeds %d bytes", max)
	}

	return data, nil
}
