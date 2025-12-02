package vendors

import "testing"

func TestIsValidVendorID(t *testing.T) {
	tests := []struct {
		name     string
		vendorID string
		want     bool
	}{
		{
			name:     "valid vendor ID - STM",
			vendorID: "STM",
			want:     true,
		},
		{
			name:     "valid vendor ID - NTC",
			vendorID: "NTC",
			want:     true,
		},
		{
			name:     "valid vendor ID - INTC",
			vendorID: "INTC",
			want:     true,
		},
		{
			name:     "invalid vendor ID - lowercase",
			vendorID: "stm",
			want:     false,
		},
		{
			name:     "invalid vendor ID - unknown",
			vendorID: "UNKNOWN",
			want:     false,
		},
		{
			name:     "invalid vendor ID - empty",
			vendorID: "",
			want:     false,
		},
		{
			name:     "invalid vendor ID - with spaces",
			vendorID: "STM ",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidVendorID(tt.vendorID); got != tt.want {
				t.Errorf("IsValidVendorID(%q) = %v, want %v", tt.vendorID, got, tt.want)
			}
		})
	}
}

func TestValidateVendorID(t *testing.T) {
	tests := []struct {
		name      string
		vendorID  string
		wantError bool
	}{
		{
			name:      "valid vendor ID",
			vendorID:  "STM",
			wantError: false,
		},
		{
			name:      "invalid vendor ID",
			vendorID:  "INVALID",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVendorID(tt.vendorID)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateVendorID(%q) error = %v, wantError %v", tt.vendorID, err, tt.wantError)
			}
		})
	}
}
