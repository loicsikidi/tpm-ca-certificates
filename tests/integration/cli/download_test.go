package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"testing"
)

func TestDownloadCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	tests := []struct {
		name             string
		date             string
		expectedChecksum string
	}{
		{
			name:             "download bundle for 2025-12-10",
			date:             "2025-12-10",
			expectedChecksum: "90ac2af61924b0db6ff40da7b8ff5b722652381410bc642b4a558eb8053e7809",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run the download command with stdout output
			cmd := exec.Command("go", "run", "../../../main.go", "bundle", "download", "--date", tt.date, "--output-dir", "-")

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Fatalf("download command failed: %v\nstderr: %s", err, stderr.String())
			}

			// Compute SHA256 checksum
			bundleData := stdout.Bytes()
			if len(bundleData) == 0 {
				t.Fatal("downloaded bundle is empty")
			}

			hash := sha256.Sum256(bundleData)
			actualChecksum := hex.EncodeToString(hash[:])

			// Verify checksum
			if actualChecksum != tt.expectedChecksum {
				t.Errorf("checksum mismatch:\nexpected: %s\ngot:      %s", tt.expectedChecksum, actualChecksum)
			}

			t.Logf("✓ Successfully downloaded and verified bundle for %s", tt.date)
			t.Logf("✓ SHA256: %s", actualChecksum)
		})
	}
}
