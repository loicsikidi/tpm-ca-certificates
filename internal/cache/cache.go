package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

const (
	// CacheDirName is the default folder name for tpmtb cache.
	CacheDirName = ".tpmtb"

	// ConfigFilename is the cache configuration file name.
	ConfigFilename = "config.json"

	// RootBundleFilename is the root bundle file name.
	RootBundleFilename = "tpm-ca-certificates.pem"

	// IntermediateBundleFilename is the intermediate bundle file name.
	IntermediateBundleFilename = "tpm-intermediate-ca-certificates.pem"

	// ChecksumsFilename is the checksums file name.
	ChecksumsFilename = "checksums.txt"

	// ChecksumsSigFilename is the checksums signature file name.
	ChecksumsSigFilename = "checksums.txt.sigstore.json"

	// ProvenanceFilename is the provenance file name.
	ProvenanceFilename = "provenance.json"

	// TrustedRootFilename is the trusted root file name.
	TrustedRootFilename = "trusted-root.json"
)

// Filenames is the list of all expected cache files.
var Filenames = []string{
	RootBundleFilename,
	IntermediateBundleFilename,
	ChecksumsFilename,
	ChecksumsSigFilename,
	ProvenanceFilename,
	TrustedRootFilename,
	ConfigFilename,
}

var (
	once sync.Once
	path string
)

// CacheDir returns the path to the cache directory.
//
// It initializes the path on the first call by determining the user's home directory
func CacheDir() string {
	once.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			// Fall back to using a tpmtb repository in the temp location
			home = os.TempDir()
		}
		path = filepath.Join(home, CacheDirName)
	})
	return path
}

// ValidateCacheFiles checks if all required cache files exist in the specified directory.
// Returns an error listing missing files if any are not found.
func ValidateCacheFiles(cacheDir string) error {
	var missingFiles []string

	for _, filename := range Filenames {
		if filename == IntermediateBundleFilename {
			// Intermediate bundle is optional
			continue
		}
		filePath := filepath.Join(cacheDir, filename)
		if !utils.FileExists(filePath) {
			missingFiles = append(missingFiles, filename)
		}
	}

	if len(missingFiles) > 0 {
		return fmt.Errorf("missing required cache files: %v", missingFiles)
	}

	return nil
}

// LoadFile reads a specified file from the cache directory.
func LoadFile(cacheDir string, filename string) ([]byte, error) {
	filePath := filepath.Join(cacheDir, filename)
	data, err := utils.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s from cache: %w", filename, err)
	}
	return data, nil
}

// SaveFile writes data to a specified file in the cache directory.
func SaveFile(cacheDir, filename string, data []byte) error {
	// Skip saving empty files
	if len(data) == 0 {
		return nil
	}

	filePath := filepath.Join(cacheDir, filename)
	perm := os.FileMode(0644)
	if filename == TrustedRootFilename {
		perm = 0600
	}
	if err := os.WriteFile(filePath, data, perm); err != nil {
		return fmt.Errorf("failed to write %s to cache: %w", filename, err)
	}
	return nil
}
