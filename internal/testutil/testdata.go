// Package testutil provides testing utilities and embedded test data.
package testutil

import (
	"bytes"
	"embed"
	"encoding/json"
	"io/fs"
	"sync"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
)

const (
	// RootBundleFile is the name of the test bundle file.
	RootBundleFile = "tpm-ca-certificates.pem"

	// ChecksumFile is the name of the test checksum file.
	ChecksumFile = "checksums.txt"

	// ChecksumSigstoreFile is the name of the test sigstore signature file.
	ChecksumSigstoreFile = "checksums.txt.sigstore.json"

	// ProvenanceFile is the name of the test provenance file.
	ProvenanceFile = "provenance.json"

	// RootConfigFile is the name of the test config file.
	RootConfigFile = ".tpm-roots.yaml"

	// IntermediateConfigFile is the name of the intermediate config file.
	IntermediateConfigFile = ".tpm-intermediates.yaml"

	// TrustedRootFile is the name of the trusted root file.
	TrustedRootFile = "trusted-root.json"

	// CacheConfigFile is the name of the cache config file.
	CacheConfigFile = "config.json"
)

// TestData contains embedded test data files from tests/integration/testdata.
//
//go:embed testdata/*
var TestData embed.FS

var (
	once          sync.Once
	BundleVersion string
)

func init() {
	once.Do(func() {
		rawBundle, err := ReadTestFile(RootBundleFile)
		if err != nil {
			panic("failed to read embedded test bundle: " + err.Error())
		}

		metadata, err := bundle.ParseMetadata(rawBundle)
		if err != nil {
			panic("failed to parse bundle metadata: " + err.Error())
		}

		BundleVersion = metadata.Date
	})
}

// GetTestDataFS returns the embedded filesystem containing test data.
// The files are located under the "testdata/" prefix.
func GetTestDataFS() fs.FS {
	sub, err := fs.Sub(TestData, "testdata")
	if err != nil {
		panic(err)
	}
	return sub
}

// ReadTestFile reads a test data file by name.
// The name should be relative to the testdata directory (e.g., "checksums.txt").
func ReadTestFile(name string) ([]byte, error) {
	return fs.ReadFile(GetTestDataFS(), name)
}

// CreateCacheDir creates a temporary cache directory with all required files
// for testing Load functionality. It returns the path to the temporary directory.
//
// The directory contains:
//   - tpm-ca-certificates.pem (bundle)
//   - checksums.txt
//   - checksums.txt.sigstore.json
//   - roots.provenance.json
//   - config.json (generated from configData parameter)
//
// The configData parameter should be a marshaled JSON representing the cache configuration.
// If nil, a minimal valid config will be created.
//
// Example:
//
//	cacheDir := testutil.CreateCacheDir(t, configJSON)
//	defer os.RemoveAll(cacheDir)
func CreateCacheDir(t *testing.T, configData []byte) string {
	tmpDir := t.TempDir()

	// Read and write test files
	rootBundleData, err := ReadTestFile(RootBundleFile)
	if err != nil {
		t.Fatalf("Failed to read test bundle: %v", err)
	}
	if err := cache.SaveFile(tmpDir, cache.RootBundleFilename, rootBundleData); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}

	checksumData, err := ReadTestFile(ChecksumFile)
	if err != nil {
		t.Fatalf("Failed to read test checksums: %v", err)
	}
	if err := cache.SaveFile(tmpDir, cache.ChecksumsFilename, checksumData); err != nil {
		t.Fatalf("Failed to write checksums: %v", err)
	}

	checksumSigData, err := ReadTestFile(ChecksumSigstoreFile)
	if err != nil {
		t.Fatalf("Failed to read test checksum signature: %v", err)
	}
	if err := cache.SaveFile(tmpDir, cache.ChecksumsSigFilename, checksumSigData); err != nil {
		t.Fatalf("Failed to write checksum signature: %v", err)
	}

	provenanceData, err := ReadTestFile(ProvenanceFile)
	if err != nil {
		t.Fatalf("Failed to read test provenance: %v", err)
	}
	if err := cache.SaveFile(tmpDir, cache.ProvenanceFilename, provenanceData); err != nil {
		t.Fatalf("Failed to write provenance: %v", err)
	}

	trustedRootData, err := ReadTestFile(TrustedRootFile)
	if err != nil {
		t.Fatalf("Failed to read test trusted root: %v", err)
	}
	if err := cache.SaveFile(tmpDir, cache.TrustedRootFilename, trustedRootData); err != nil {
		t.Fatalf("Failed to write trusted root: %v", err)
	}

	// Write config
	if configData == nil {
		// Create minimal valid config with bundle version
		b, err := ReadTestFile(CacheConfigFile)
		if err != nil {
			t.Fatalf("Failed to read test cache config: %v", err)
		}
		configData = bytes.Clone(b)
	}

	// Validate it's valid JSON
	var tmp any
	if err := json.Unmarshal(configData, &tmp); err != nil {
		t.Fatalf("Invalid config JSON: %v", err)
	}

	if err := cache.SaveFile(tmpDir, cache.ConfigFilename, configData); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	return tmpDir
}
