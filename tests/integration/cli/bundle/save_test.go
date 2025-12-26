package bundle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/save"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func TestSaveCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that downloads bundle from remote")
	}

	tests := []struct {
		name           string
		opts           save.Opts
		expectError    bool
		validateResult func(t *testing.T, outputDir string)
	}{
		{
			name: "save latest bundle to output directory",
			opts: save.Opts{
				Date:       "",
				VendorIDs:  nil,
				OutputDir:  "",
				Force:      true,
				LocalCache: false,
			},
			expectError: false,
			validateResult: func(t *testing.T, outputDir string) {
				for _, filename := range apiv1beta.CacheFilenames {
					filePath := filepath.Join(outputDir, filename)
					if _, err := os.Stat(filePath); os.IsNotExist(err) {
						t.Errorf("expected file %s to exist, but it does not", filename)
					}
				}
			},
		},
		{
			name: "save specific date bundle",
			opts: save.Opts{
				Date:       testutil.BundleVersion,
				VendorIDs:  nil,
				OutputDir:  "",
				Force:      true,
				LocalCache: false,
			},
			expectError: false,
			validateResult: func(t *testing.T, outputDir string) {
				bundlePath := filepath.Join(outputDir, apiv1beta.CacheRootBundleFilename)
				data, err := os.ReadFile(bundlePath)
				if err != nil {
					t.Fatalf("failed to read bundle file: %v", err)
				}
				if len(data) == 0 {
					t.Error("bundle file is empty")
				}
			},
		},
		{
			name: "save bundle filtered by vendor IDs",
			opts: save.Opts{
				Date:       "",
				VendorIDs:  []string{"IFX", "NTC"},
				OutputDir:  "",
				Force:      true,
				LocalCache: false,
			},
			expectError: false,
			validateResult: func(t *testing.T, outputDir string) {
				configPath := filepath.Join(outputDir, apiv1beta.CacheConfigFilename)
				if _, err := os.Stat(configPath); os.IsNotExist(err) {
					t.Errorf("expected config file to exist")
				}
			},
		},
		{
			name: "error when output directory does not exist",
			opts: save.Opts{
				Date:       "",
				VendorIDs:  nil,
				OutputDir:  "/nonexistent/directory",
				Force:      true,
				LocalCache: false,
			},
			expectError: true,
		},
		{
			name: "error with invalid vendor ID",
			opts: save.Opts{
				Date:       "",
				VendorIDs:  []string{"INVALID_VENDOR"},
				OutputDir:  "",
				Force:      true,
				LocalCache: false,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if tt.opts.OutputDir == "" {
				tt.opts.OutputDir = tmpDir
			}

			// Run the save command
			err := save.Run(t.Context(), &tt.opts)

			// Check error expectation
			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Validate result if no error expected
			if !tt.expectError && tt.validateResult != nil {
				tt.validateResult(t, tmpDir)
			}
		})
	}
}

func TestSaveCommandForceFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that downloads bundle from remote")
	}

	t.Run("overwrite existing files with force flag", func(t *testing.T) {
		tmpDir := t.TempDir()

		// First save
		opts := save.Opts{
			Date:       "",
			VendorIDs:  nil,
			OutputDir:  tmpDir,
			Force:      true,
			LocalCache: false,
		}

		err := save.Run(t.Context(), &opts)
		if err != nil {
			t.Fatalf("first save failed: %v", err)
		}

		// Second save with force flag should succeed
		err = save.Run(t.Context(), &opts)
		if err != nil {
			t.Fatalf("second save with force flag failed: %v", err)
		}

		// Verify files still exist
		bundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
		if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
			t.Error("bundle file should exist after overwrite")
		}
	})
}
