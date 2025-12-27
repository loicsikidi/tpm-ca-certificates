package bundle_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/generate"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestGenerateCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that requires network access")
	}

	tmpDir := t.TempDir()

	// Prepare root config file
	rootConfigPath := tmpDir + "/" + testutil.RootConfigFile
	rootConfigData, err := testutil.ReadTestFile(testutil.RootConfigFile)
	if err != nil {
		t.Fatalf("failed to read root config file: %v", err)
	}
	if err := os.WriteFile(rootConfigPath, rootConfigData, 0644); err != nil {
		t.Fatalf("failed to write root config file: %v", err)
	}

	// Prepare intermediate config file
	intermediateConfigPath := tmpDir + "/.tpm-intermediates.yaml"
	intermediateConfigData, err := testutil.ReadTestFile(testutil.IntermediateConfigFile)
	if err != nil {
		t.Fatalf("failed to read intermediate config file: %v", err)
	}
	if err := os.WriteFile(intermediateConfigPath, intermediateConfigData, 0644); err != nil {
		t.Fatalf("failed to write intermediate config file: %v", err)
	}

	tests := []struct {
		name                 string
		configPath           string
		outputFilename       string
		typeFlag             string
		expectedHeaderSubstr string
	}{
		{
			name:                 "generate root bundle with explicit type flag",
			configPath:           rootConfigPath,
			outputFilename:       "tpm-root-ca-certificates.pem",
			typeFlag:             "root",
			expectedHeaderSubstr: "## and contains a list of verified TPM Root Endorsement Certificates.",
		},
		{
			name:                 "generate root bundle without type flag (auto-detect)",
			configPath:           rootConfigPath,
			outputFilename:       "tpm-root-ca-certificates.pem",
			typeFlag:             "",
			expectedHeaderSubstr: "## and contains a list of verified TPM Root Endorsement Certificates.",
		},
		{
			name:                 "generate intermediate bundle with explicit type flag",
			configPath:           intermediateConfigPath,
			outputFilename:       "tpm-intermediate-ca-certificates.pem",
			typeFlag:             "intermediate",
			expectedHeaderSubstr: "## and contains a list of verified TPM Intermediate Endorsement Certificates.",
		},
		{
			name:                 "generate intermediate bundle without type flag (auto-detect from filename)",
			configPath:           intermediateConfigPath,
			outputFilename:       "tpm-intermediate-ca-certificates.pem",
			typeFlag:             "",
			expectedHeaderSubstr: "## and contains a list of verified TPM Intermediate Endorsement Certificates.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := tmpDir + "/" + tt.outputFilename

			opts := &generate.Opts{
				ConfigPath: tt.configPath,
				OutputPath: outputPath,
				Workers:    2,
				Date:       "2025-01-01",
				Commit:     "0000000000000000000000000000000000000000",
				Type:       tt.typeFlag,
			}

			ctx := context.Background()
			if err := generate.Run(ctx, opts); err != nil {
				t.Fatalf("generate command failed: %v", err)
			}

			bundleData, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("failed to read generated bundle: %v", err)
			}

			if len(bundleData) == 0 {
				t.Fatal("generated bundle is empty")
			}

			bundleStr := string(bundleData)

			if !strings.Contains(bundleStr, tt.expectedHeaderSubstr) {
				t.Errorf("bundle does not contain expected header substring:\nexpected: %s\ngot first 500 chars:\n%s",
					tt.expectedHeaderSubstr, bundleStr[:min(500, len(bundleStr))])
			}

			if !strings.Contains(bundleStr, tt.outputFilename) {
				t.Errorf("bundle does not contain expected filename:\nexpected: %s\ngot first 500 chars:\n%s",
					tt.outputFilename, bundleStr[:min(500, len(bundleStr))])
			}

			if !strings.Contains(bundleStr, "-----BEGIN CERTIFICATE-----") {
				t.Error("bundle does not contain any certificates")
			}

			t.Logf("✓ Successfully generated %s", tt.name)
		})
	}
}

func TestGenerateCommand_InvalidType(t *testing.T) {
	// Create a temporary directory for the config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/" + testutil.RootConfigFile

	// Copy the root config file to temp directory
	rootConfigData, err := testutil.ReadTestFile(testutil.RootConfigFile)
	if err != nil {
		t.Fatalf("failed to read root config file: %v", err)
	}
	if err := os.WriteFile(configPath, rootConfigData, 0644); err != nil {
		t.Fatalf("failed to write root config file: %v", err)
	}

	// Create generate options with invalid type
	opts := &generate.Opts{
		ConfigPath: configPath,
		OutputPath: "",
		Workers:    2,
		Date:       "2025-01-01",
		Commit:     "0000000000000000000000000000000000000000",
		Type:       "invalid",
	}

	// Run generate (should fail)
	ctx := context.Background()
	err = generate.Run(ctx, opts)
	if err == nil {
		t.Fatal("expected error for invalid bundle type, but got nil")
	}

	// Check that the error message contains the expected text
	expectedErrMsg := "invalid bundle type"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("expected error to contain %q, but got: %v", expectedErrMsg, err)
	}

	t.Logf("✓ Correctly rejected invalid bundle type")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
