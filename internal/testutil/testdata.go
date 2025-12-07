// Package testutil provides testing utilities and embedded test data.
package testutil

import (
	"embed"
	"io/fs"
)

const (
	// BundleFile is the name of the test bundle file.
	BundleFile = "tpm-ca-certificates.pem"

	// ChecksumFile is the name of the test checksum file.
	ChecksumFile = "checksums.txt"

	// ChecksumSigstoreFile is the name of the test sigstore signature file.
	ChecksumSigstoreFile = "checksums.txt.sigstore.json"
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
