package fingerprint_test

import (
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
)

func TestNew(t *testing.T) {
	testData := []byte("test data")

	tests := []struct {
		name      string
		algorithm string
		wantPanic bool
	}{
		{
			name:      "SHA1",
			algorithm: fingerprint.SHA1,
			wantPanic: false,
		},
		{
			name:      "SHA256",
			algorithm: fingerprint.SHA256,
			wantPanic: false,
		},
		{
			name:      "SHA384",
			algorithm: fingerprint.SHA384,
			wantPanic: false,
		},
		{
			name:      "SHA512",
			algorithm: fingerprint.SHA512,
			wantPanic: false,
		},
		{
			name:      "invalid algorithm",
			algorithm: "invalid",
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.wantPanic {
					t.Errorf("fingerprint.New() panic = %v, wantPanic %v", r, tt.wantPanic)
				}
			}()

			result := fingerprint.New(testData, tt.algorithm)
			if !tt.wantPanic {
				// Verify result is in correct format (uppercase with colons)
				if result == "" {
					t.Errorf("fingerprint.New() returned empty string")
				}
				for i, c := range result {
					if i%3 == 2 { // Every 3rd character should be a colon
						if c != ':' {
							t.Errorf("fingerprint.New() character at position %d should be ':', got %c", i, c)
						}
					} else {
						// Should be uppercase hex digit
						if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
							t.Errorf("fingerprint.New() character at position %d should be uppercase hex, got %c", i, c)
						}
					}
				}
			}
		})
	}
}
