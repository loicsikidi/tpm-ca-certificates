package validate_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/validate"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
)

func TestValidateFingerprintWithAlgorithm(t *testing.T) {
	cert, sha1Fingerprint := testutil.GenerateTestCert(t)

	sha256Actual := hex.EncodeToString(digest.Sha256Hash(cert.Raw))
	sha384Actual := hex.EncodeToString(digest.Sha384Hash(cert.Raw))
	sha512Actual := hex.EncodeToString(digest.Sha512Hash(cert.Raw))

	tests := []struct {
		name               string
		expectedFP         string
		algorithm          string
		wantError          bool
		errorShouldContain string
	}{
		{
			name:       "valid SHA1 with colons",
			expectedFP: fingerprint.FormatFingerprint(sha1Fingerprint),
			algorithm:  fingerprint.SHA1,
			wantError:  false,
		},
		{
			name:       "valid SHA1 without colons",
			expectedFP: sha1Fingerprint,
			algorithm:  fingerprint.SHA1,
			wantError:  false,
		},
		{
			name:       "valid SHA256 with colons",
			expectedFP: fingerprint.FormatFingerprint(sha256Actual),
			algorithm:  fingerprint.SHA256,
			wantError:  false,
		},
		{
			name:       "valid SHA256 without colons",
			expectedFP: sha256Actual,
			algorithm:  fingerprint.SHA256,
			wantError:  false,
		},
		{
			name:       "valid SHA384",
			expectedFP: fingerprint.FormatFingerprint(sha384Actual),
			algorithm:  fingerprint.SHA384,
			wantError:  false,
		},
		{
			name:       "valid SHA512",
			expectedFP: fingerprint.FormatFingerprint(sha512Actual),
			algorithm:  fingerprint.SHA512,
			wantError:  false,
		},
		{
			name:               "invalid SHA1 fingerprint",
			expectedFP:         "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
			algorithm:          fingerprint.SHA1,
			wantError:          true,
			errorShouldContain: "fingerprint mismatch",
		},
		{
			name:               "invalid SHA256 fingerprint",
			expectedFP:         "0000000000000000000000000000000000000000000000000000000000000000",
			algorithm:          fingerprint.SHA256,
			wantError:          true,
			errorShouldContain: "fingerprint mismatch",
		},
		{
			name:               "wrong algorithm used (SHA256 expected, SHA1 provided)",
			expectedFP:         sha1Fingerprint,
			algorithm:          fingerprint.SHA256,
			wantError:          true,
			errorShouldContain: "fingerprint mismatch",
		},
		{
			name:       "case insensitive matching lowercase",
			expectedFP: strings.ToLower(sha256Actual),
			algorithm:  fingerprint.SHA256,
			wantError:  false,
		},
		{
			name:       "case insensitive matching uppercase",
			expectedFP: strings.ToUpper(sha256Actual),
			algorithm:  fingerprint.SHA256,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.ValidateFingerprintWithAlgorithm(cert, tt.expectedFP, tt.algorithm)

			if tt.wantError && err == nil {
				t.Errorf("ValidateFingerprintWithAlgorithm() expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateFingerprintWithAlgorithm() unexpected error = %v", err)
			}
			if tt.wantError && err != nil && tt.errorShouldContain != "" {
				if !strings.Contains(err.Error(), tt.errorShouldContain) {
					t.Errorf("ValidateFingerprintWithAlgorithm() error = %v, should contain %q", err, tt.errorShouldContain)
				}
			}
		})
	}
}

func TestValidateFingerprint(t *testing.T) {
	cert, fp := testutil.GenerateTestCert(t)

	sha1Actual := fp
	sha256Actual := hex.EncodeToString(digest.Sha256Hash(cert.Raw))

	tests := []struct {
		name        string
		fingerprint config.Fingerprint
		wantError   bool
	}{
		{
			name: "valid SHA1 with colons",
			fingerprint: config.Fingerprint{
				SHA1: fingerprint.FormatFingerprint(sha1Actual),
			},
			wantError: false,
		},
		{
			name: "valid SHA1 without colons",
			fingerprint: config.Fingerprint{
				SHA1: sha1Actual,
			},
			wantError: false,
		},
		{
			name: "valid SHA256",
			fingerprint: config.Fingerprint{
				SHA256: fingerprint.FormatFingerprint(sha256Actual),
			},
			wantError: false,
		},
		{
			name: "invalid SHA1",
			fingerprint: config.Fingerprint{
				SHA1: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
			},
			wantError: true,
		},
		{
			name: "invalid SHA256",
			fingerprint: config.Fingerprint{
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			},
			wantError: true,
		},
		{
			name:        "no fingerprints provided",
			fingerprint: config.Fingerprint{},
			wantError:   true,
		},
		{
			name: "malformed fingerprint",
			fingerprint: config.Fingerprint{
				SHA1: "not-a-hex-string",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.ValidateFingerprint(cert, tt.fingerprint)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateFingerprint() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
