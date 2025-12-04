package generate

import (
	"testing"
)

func Test_validateDate(t *testing.T) {
	tests := []struct {
		name        string
		date        string
		expectError bool
	}{
		{
			name:        "valid date",
			date:        "2024-06-15",
			expectError: false,
		},
		{
			name:        "valid date with leading zeros",
			date:        "2024-01-01",
			expectError: false,
		},
		{
			name:        "invalid format - missing day",
			date:        "2024-06",
			expectError: true,
		},
		{
			name:        "invalid format - wrong separator",
			date:        "2024/06/15",
			expectError: true,
		},
		{
			name:        "invalid format - not a date",
			date:        "not-a-date",
			expectError: true,
		},
		{
			name:        "invalid format - incomplete",
			date:        "2024-06-1",
			expectError: true,
		},
		{
			name:        "empty date",
			date:        "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDate(tt.date)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func Test_validateCommit(t *testing.T) {
	tests := []struct {
		name        string
		commit      string
		expectError bool
	}{
		{
			name:        "valid commit hash",
			commit:      "a1b2c3d4e5f67890123456789abcdef012345678",
			expectError: false,
		},
		{
			name:        "valid commit hash - all lowercase",
			commit:      "fedcba9876543210fedcba9876543210fedcba98",
			expectError: false,
		},
		{
			name:        "invalid - uppercase letters",
			commit:      "A1B2C3D4E5F67890123456789ABCDEF012345678",
			expectError: true,
		},
		{
			name:        "invalid - too short",
			commit:      "a1b2c3d4e5f67890123456789abcdef0123456",
			expectError: true,
		},
		{
			name:        "invalid - too long",
			commit:      "a1b2c3d4e5f67890123456789abcdef0123456789",
			expectError: true,
		},
		{
			name:        "invalid - contains non-hex characters",
			commit:      "g1b2c3d4e5f67890123456789abcdef012345678",
			expectError: true,
		},
		{
			name:        "empty commit",
			commit:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommit(tt.commit)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
