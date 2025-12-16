package list

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/spf13/cobra"
)

var (
	limit     int
	sortOrder string
)

// NewCommand creates the list command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "list available TPM trust bundle releases",
		Long: `List publicly available TPM trust bundle releases from GitHub.

Only releases with date-format tags (YYYY-MM-DD) are displayed, as these
represent TPM trust bundle releases. Semantic version releases (like v1.0.0)
are ignored.`,
		Example: `  # List the last 10 releases (default)
  tpmtb bundle list

  # List the last 20 releases
  tpmtb bundle list --limit 20

  # List releases in ascending order (oldest first)
  tpmtb bundle list --sort asc

  # List the last 5 releases in descending order
  tpmtb bundle list --limit 5 --sort desc`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().IntVarP(&limit, "limit", "l", 10,
		"Maximum number of releases to display")
	cmd.Flags().StringVarP(&sortOrder, "sort", "s", "desc",
		"Sort order for releases: asc (oldest first) or desc (newest first)")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	// Validate sort order
	var order github.SortOrder
	switch sortOrder {
	case "asc":
		order = github.SortOrderAsc
	case "desc":
		order = github.SortOrderDesc
	default:
		return fmt.Errorf("invalid sort order %q, must be 'asc' or 'desc'", sortOrder)
	}

	// Validate limit
	if limit <= 0 {
		return fmt.Errorf("limit must be greater than 0")
	}

	client := github.NewHTTPClient()

	opts := github.ReleasesOptions{
		PageSize:  limit,
		SortOrder: order,
	}

	releases, err := client.GetReleases(cmd.Context(), github.SourceRepo, opts)
	if err != nil {
		return fmt.Errorf("failed to fetch releases: %w", err)
	}

	if len(releases) == 0 {
		fmt.Println("No bundle releases found")
		return nil
	}

	// Apply limit if we got more releases than requested
	if len(releases) > limit {
		releases = releases[:limit]
	}

	fmt.Printf("Available TPM trust bundle releases (%d):\n", len(releases))
	for _, release := range releases {
		fmt.Printf("  %s\n", release.TagName)
	}

	return nil
}
