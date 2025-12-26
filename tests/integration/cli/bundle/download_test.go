package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/download"
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
			// Capture stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdout = w

			// Create download config
			opts := &download.Opts{
				Date:       tt.date,
				OutputDir:  "-",
				SkipVerify: false,
				Force:      false,
			}

			// Run download in a goroutine
			errCh := make(chan error, 1)
			go func() {
				errCh <- download.Run(t.Context(), opts)
			}()

			// Read output
			var stdout bytes.Buffer
			done := make(chan bool)
			go func() {
				_, _ = io.Copy(&stdout, r)
				done <- true
			}()

			// Wait for command to finish
			if err := <-errCh; err != nil {
				w.Close()
				<-done
				os.Stdout = oldStdout
				t.Fatalf("download command failed: %v", err)
			}

			// Close pipe and restore stdout
			w.Close()
			<-done
			os.Stdout = oldStdout

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
