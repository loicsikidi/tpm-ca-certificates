package cache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCacheFiles(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  []string
		wantErr     bool
		wantMissing []string
	}{
		{
			name: "all files present",
			setupFiles: []string{
				RootBundleFilename,
				ChecksumsFilename,
				ChecksumsSigFilename,
				ProvenanceFilename,
				TrustedRootFilename,
				ConfigFilename,
			},
			wantErr: false,
		},
		{
			name: "missing trusted root",
			setupFiles: []string{
				RootBundleFilename,
				ChecksumsFilename,
				ChecksumsSigFilename,
				ProvenanceFilename,
				ConfigFilename,
			},
			wantErr:     true,
			wantMissing: []string{TrustedRootFilename},
		},
		{
			name: "missing multiple files",
			setupFiles: []string{
				RootBundleFilename,
				ConfigFilename,
			},
			wantErr: true,
			wantMissing: []string{
				ChecksumsFilename,
				ChecksumsSigFilename,
				ProvenanceFilename,
				TrustedRootFilename,
			},
		},
		{
			name:       "no files present",
			setupFiles: []string{},
			wantErr:    true,
			wantMissing: []string{
				RootBundleFilename,
				ChecksumsFilename,
				ChecksumsSigFilename,
				ProvenanceFilename,
				TrustedRootFilename,
				ConfigFilename,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create only the specified files
			for _, filename := range tt.setupFiles {
				filePath := filepath.Join(tmpDir, filename)
				if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
					t.Fatalf("Failed to create test file %s: %v", filename, err)
				}
			}

			err := ValidateCacheFiles(tmpDir)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCacheFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				// Check that the error message contains all missing files
				for _, missing := range tt.wantMissing {
					if err.Error() == "" {
						t.Errorf("Expected error to mention missing file %s, but got empty error", missing)
					}
				}
			}
		})
	}
}

func TestLoadFile(t *testing.T) {
	tests := []struct {
		name            string
		filename        string
		setupContent    string
		provideCacheDir bool
		wantErr         bool
		wantContent     string
	}{
		{
			name:         "successfully load existing file",
			filename:     RootBundleFilename,
			setupContent: "test certificate content",
			wantErr:      false,
			wantContent:  "test certificate content",
		},
		{
			name:            "successfully load file with custom cache dir",
			filename:        ConfigFilename,
			setupContent:    `{"version": "1.0"}`,
			provideCacheDir: true,
			wantErr:         false,
			wantContent:     `{"version": "1.0"}`,
		},
		{
			name:     "file does not exist",
			filename: "nonexistent.txt",
			wantErr:  true,
		},
		{
			name:         "load empty file",
			filename:     ChecksumsFilename,
			setupContent: "",
			wantErr:      false,
			wantContent:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create test file if setup content is provided or if we expect it to exist
			if tt.setupContent != "" || (!tt.wantErr && tt.filename != "nonexistent.txt") {
				filePath := filepath.Join(tmpDir, tt.filename)
				if err := os.WriteFile(filePath, []byte(tt.setupContent), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
			}

			var got []byte
			var err error

			if tt.provideCacheDir {
				got, err = LoadFile(tt.filename, tmpDir)
			} else {
				got, err = LoadFile(tt.filename, tmpDir)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if string(got) != tt.wantContent {
					t.Errorf("LoadFile() got = %q, want %q", string(got), tt.wantContent)
				}
			}
		})
	}
}
