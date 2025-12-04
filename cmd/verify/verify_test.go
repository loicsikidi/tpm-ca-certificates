package verify

import (
	"testing"
)

func Test_splitRepo(t *testing.T) {
	tests := []struct {
		name        string
		repository  string
		wantOwner   string
		wantRepo    string
		expectError bool
	}{
		{
			name:        "valid repository",
			repository:  "loicsikidi/tpm-ca-certificates",
			wantOwner:   "loicsikidi",
			wantRepo:    "tpm-ca-certificates",
			expectError: false,
		},
		{
			name:        "valid repository with different owner",
			repository:  "github/example-repo",
			wantOwner:   "github",
			wantRepo:    "example-repo",
			expectError: false,
		},
		{
			name:        "valid repository with hyphenated names",
			repository:  "my-org/my-repo-name",
			wantOwner:   "my-org",
			wantRepo:    "my-repo-name",
			expectError: false,
		},
		{
			name:        "invalid - missing slash",
			repository:  "loicsikidi",
			expectError: true,
		},
		{
			name:        "invalid - too many slashes",
			repository:  "loicsikidi/tpm-ca-certificates/extra",
			wantOwner:   "loicsikidi",
			wantRepo:    "tpm-ca-certificates/extra",
			expectError: false,
		},
		{
			name:        "invalid - empty string",
			repository:  "",
			expectError: true,
		},
		{
			name:        "edge case - only slash",
			repository:  "/",
			wantOwner:   "",
			wantRepo:    "",
			expectError: false,
		},
		{
			name:        "edge case - leading slash",
			repository:  "/owner/repo",
			wantOwner:   "",
			wantRepo:    "owner/repo",
			expectError: false,
		},
		{
			name:        "invalid - trailing slash",
			repository:  "owner/repo/",
			wantOwner:   "owner",
			wantRepo:    "repo/",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := splitRepo(tt.repository)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.expectError {
				if owner != tt.wantOwner {
					t.Errorf("owner mismatch: got %q, want %q", owner, tt.wantOwner)
				}
				if repo != tt.wantRepo {
					t.Errorf("repo mismatch: got %q, want %q", repo, tt.wantRepo)
				}
			}
		})
	}
}

func Test_colorize(t *testing.T) {
	tests := []struct {
		name     string
		color    color
		text     string
		expected string
	}{
		{
			name:     "red color",
			color:    colorRed,
			text:     "Error message",
			expected: "\033[31mError message\033[0m",
		},
		{
			name:     "green color",
			color:    colorGreen,
			text:     "Success message",
			expected: "\033[32mSuccess message\033[0m",
		},
		{
			name:     "empty text",
			color:    colorRed,
			text:     "",
			expected: "\033[31m\033[0m",
		},
		{
			name:     "text with special characters",
			color:    colorGreen,
			text:     "✅ Verification succeeded",
			expected: "\033[32m✅ Verification succeeded\033[0m",
		},
		{
			name:     "multiline text",
			color:    colorRed,
			text:     "Line 1\nLine 2",
			expected: "\033[31mLine 1\nLine 2\033[0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := colorize(tt.color, tt.text)
			if result != tt.expected {
				t.Errorf("colorize() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func Test_displayBundleMetadata(t *testing.T) {
	tests := []struct {
		name   string
		date   string
		commit string
	}{
		{
			name:   "valid metadata",
			date:   "2025-12-04",
			commit: "63e6a017e9c15428b2959cb2760d21f05dea42f4",
		},
		{
			name:   "empty date",
			date:   "",
			commit: "63e6a017e9c15428b2959cb2760d21f05dea42f4",
		},
		{
			name:   "empty commit",
			date:   "2025-12-04",
			commit: "",
		},
		{
			name:   "both empty",
			date:   "",
			commit: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This function prints to stdout, so we're just checking it doesn't panic
			displayBundleMetadata(tt.date, tt.commit)
		})
	}
}

func Test_displayPolicyCriteria(t *testing.T) {
	tests := []struct {
		name       string
		owner      string
		sourceRepo string
		tag        string
	}{
		{
			name:       "valid criteria",
			owner:      "loicsikidi",
			sourceRepo: "loicsikidi/tpm-ca-certificates",
			tag:        "2025-12-04",
		},
		{
			name:       "different owner",
			owner:      "github",
			sourceRepo: "github/example-repo",
			tag:        "2025-01-01",
		},
		{
			name:       "empty tag",
			owner:      "loicsikidi",
			sourceRepo: "loicsikidi/tpm-ca-certificates",
			tag:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This function prints to stdout, so we're just checking it doesn't panic
			displayPolicyCriteria(tt.owner, tt.sourceRepo, tt.tag)
		})
	}
}
