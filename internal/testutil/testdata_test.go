package testutil_test

import (
	"io/fs"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestReadTestFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "checksums.txt exists",
			filename: "checksums.txt",
			wantErr:  false,
		},
		{
			name:     "checksums.txt.sigstore.json exists",
			filename: "checksums.txt.sigstore.json",
			wantErr:  false,
		},
		{
			name:     "tpm-ca-certificates.pem exists",
			filename: "tpm-ca-certificates.pem",
			wantErr:  false,
		},
		{
			name:     "non-existent file",
			filename: "does-not-exist.txt",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := testutil.ReadTestFile(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadTestFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(data) == 0 {
				t.Errorf("ReadTestFile() returned empty data for %s", tt.filename)
			}
		})
	}
}

func TestGetTestDataFS(t *testing.T) {
	fsys := testutil.GetTestDataFS()
	if fsys == nil {
		t.Fatal("GetTestDataFS() returned nil")
	}

	// Verify we can read a known file
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	if len(entries) == 0 {
		t.Error("GetTestDataFS() returned empty filesystem")
	}
}
