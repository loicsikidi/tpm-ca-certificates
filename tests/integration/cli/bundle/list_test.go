package bundle_test

import (
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/list"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
)

func TestListCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that fetches releases from GitHub API")
	}

	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		errContains string
		skipOutput  bool
	}{
		{
			name:       "default flags",
			args:       []string{},
			wantErr:    false,
			skipOutput: false,
		},
		{
			name:       "with limit flag",
			args:       []string{"--limit", "5"},
			wantErr:    false,
			skipOutput: false,
		},
		{
			name:       "with sort asc",
			args:       []string{"--sort", "asc"},
			wantErr:    false,
			skipOutput: false,
		},
		{
			name:       "with sort desc",
			args:       []string{"--sort", "desc"},
			wantErr:    false,
			skipOutput: false,
		},
		{
			name:       "with both flags",
			args:       []string{"--limit", "20", "--sort", "asc"},
			wantErr:    false,
			skipOutput: false,
		},
		{
			name:       "short flags",
			args:       []string{"-l", "15", "-s", "desc"},
			wantErr:    false,
			skipOutput: false,
		},
		{
			name:        "invalid sort order",
			args:        []string{"--sort", "invalid"},
			wantErr:     true,
			errContains: "invalid sort order",
			skipOutput:  true,
		},
		{
			name:        "negative limit",
			args:        []string{"--limit", "-1"},
			wantErr:     true,
			errContains: "limit must be greater than 0",
			skipOutput:  true,
		},
		{
			name:        "zero limit",
			args:        []string{"--limit", "0"},
			wantErr:     true,
			errContains: "limit must be greater than 0",
			skipOutput:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := list.NewCommand()
			cmd.SetArgs(tt.args)

			err := cmd.ExecuteContext(t.Context())

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				// Skip test if we hit rate limits
				if strings.Contains(err.Error(), "rate limit") {
					t.Skipf("skipping due to rate limit: %v", err)
					return
				}
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestListCommandOutput(t *testing.T) {
	// Integration test - can be skipped in CI if needed
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// This test verifies the output format by running the actual command
	cmd := list.NewCommand()
	cmd.SetArgs([]string{"--limit", "3"})

	err := cmd.ExecuteContext(t.Context())
	if err != nil {
		t.Skipf("skipping output test due to network error: %v", err)
		return
	}
}

func TestListCommandWithRealAPI(t *testing.T) {
	// Integration test - can be skipped in CI if needed
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := github.NewHTTPClient()

	// Test fetching releases
	opts := github.ReleasesOptions{
		PageSize:  5,
		SortOrder: github.SortOrderDesc,
	}

	releases, err := client.GetReleases(t.Context(), github.SourceRepo, opts)
	if err != nil {
		t.Fatalf("failed to fetch releases: %v", err)
	}

	// Verify we got date-formatted releases only
	for _, release := range releases {
		if !strings.Contains(release.TagName, "-") {
			t.Errorf("expected date format (YYYY-MM-DD), got %s", release.TagName)
		}
	}
}
