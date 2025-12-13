// Package testutil provides testing utilities and embedded test data.
package testutil

import (
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

const (
	// BundleFile is the name of the test bundle file.
	BundleFile = "tpm-ca-certificates.pem"

	// ChecksumFile is the name of the test checksum file.
	ChecksumFile = "checksums.txt"

	// ChecksumSigstoreFile is the name of the test sigstore signature file.
	ChecksumSigstoreFile = "checksums.txt.sigstore.json"

	// ProvenanceFile is the name of the test provenance file.
	ProvenanceFile = "roots.provenance.json"

	// ConfigFile is the name of the test config file.
	ConfigFile = ".tpm-roots.yaml"
)

// TestData contains embedded test data files from tests/integration/testdata.
//
//go:embed testdata/*
var TestData embed.FS

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
	bundleData, err := ReadTestFile(BundleFile)
	if err != nil {
		t.Fatalf("Failed to read test bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "tpm-ca-certificates.pem"), bundleData, 0644); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}

	checksumData, err := ReadTestFile(ChecksumFile)
	if err != nil {
		t.Fatalf("Failed to read test checksums: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "checksums.txt"), checksumData, 0644); err != nil {
		t.Fatalf("Failed to write checksums: %v", err)
	}

	checksumSigData, err := ReadTestFile(ChecksumSigstoreFile)
	if err != nil {
		t.Fatalf("Failed to read test checksum signature: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "checksums.txt.sigstore.json"), checksumSigData, 0644); err != nil {
		t.Fatalf("Failed to write checksum signature: %v", err)
	}

	provenanceData, err := ReadTestFile(ProvenanceFile)
	if err != nil {
		t.Fatalf("Failed to read test provenance: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "roots.provenance.json"), provenanceData, 0644); err != nil {
		t.Fatalf("Failed to write provenance: %v", err)
	}

	// Write config
	if configData == nil {
		// Create minimal valid config
		configData = []byte(`{"autoUpdate":{},"vendorIDs":[],"lastTimestamp":"2025-12-14T00:00:00Z"}`)
	}

	// Validate it's valid JSON
	var tmp any
	if err := json.Unmarshal(configData, &tmp); err != nil {
		t.Fatalf("Invalid config JSON: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), configData, 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	return tmpDir
}
