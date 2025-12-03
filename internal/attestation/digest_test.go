package attestation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeSHA256(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantDigest  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "empty file",
			content:    "",
			wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:       "simple content",
			content:    "hello world\n",
			wantDigest: "sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
		},
		{
			name:       "binary content",
			content:    "\x00\x01\x02\x03",
			wantDigest: "sha256:054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.txt")

			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			// Compute digest
			got, err := ComputeSHA256(tmpFile)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ComputeSHA256() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ComputeSHA256() unexpected error: %v", err)
				return
			}

			if got != tt.wantDigest {
				t.Errorf("ComputeSHA256() = %q, want %q", got, tt.wantDigest)
			}
		})
	}
}

func TestComputeSHA256_NonExistentFile(t *testing.T) {
	_, err := ComputeSHA256("/nonexistent/file.txt")
	if err == nil {
		t.Error("ComputeSHA256() expected error for non-existent file, got nil")
	}
}
