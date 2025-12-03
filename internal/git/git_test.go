package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetInfo(t *testing.T) {
	tests := []struct {
		name           string
		setupRepo      func(t *testing.T, repoDir string)
		expectError    bool
		validateResult func(t *testing.T, info *Info)
	}{
		{
			name: "normal git repository with branch",
			setupRepo: func(t *testing.T, repoDir string) {
				// Create .git directory structure
				gitDir := filepath.Join(repoDir, ".git")
				if err := os.MkdirAll(gitDir, 0755); err != nil {
					t.Fatal(err)
				}

				// Create refs/heads/main
				refsHeads := filepath.Join(gitDir, "refs", "heads")
				if err := os.MkdirAll(refsHeads, 0755); err != nil {
					t.Fatal(err)
				}

				commitHash := "a1b2c3d4e5f67890123456789abcdef012345678"
				if err := os.WriteFile(filepath.Join(refsHeads, "main"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}

				// Create HEAD pointing to refs/heads/main
				if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, info *Info) {
				expectedCommit := "a1b2c3d4e5f67890123456789abcdef012345678"
				if info.Commit != expectedCommit {
					t.Errorf("expected commit %s, got %s", expectedCommit, info.Commit)
				}
				if info.Branch != "main" {
					t.Errorf("expected branch 'main', got '%s'", info.Branch)
				}
			},
		},
		{
			name: "detached HEAD state",
			setupRepo: func(t *testing.T, repoDir string) {
				gitDir := filepath.Join(repoDir, ".git")
				if err := os.MkdirAll(gitDir, 0755); err != nil {
					t.Fatal(err)
				}

				// HEAD contains direct commit hash (detached state)
				commitHash := "fedcba9876543210fedcba9876543210fedcba98"
				if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, info *Info) {
				expectedCommit := "fedcba9876543210fedcba9876543210fedcba98"
				if info.Commit != expectedCommit {
					t.Errorf("expected commit %s, got %s", expectedCommit, info.Commit)
				}
				if info.Branch != "" {
					t.Errorf("expected empty branch for detached HEAD, got '%s'", info.Branch)
				}
			},
		},
		{
			name: "repository with tag pointing to current commit",
			setupRepo: func(t *testing.T, repoDir string) {
				gitDir := filepath.Join(repoDir, ".git")
				if err := os.MkdirAll(gitDir, 0755); err != nil {
					t.Fatal(err)
				}

				commitHash := "abc123def456789abc123def456789abc123def4"

				// Create detached HEAD
				if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}

				// Create tag pointing to same commit
				refsTags := filepath.Join(gitDir, "refs", "tags")
				if err := os.MkdirAll(refsTags, 0755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(refsTags, "2024-06-15"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, info *Info) {
				expectedCommit := "abc123def456789abc123def456789abc123def4"
				if info.Commit != expectedCommit {
					t.Errorf("expected commit %s, got %s", expectedCommit, info.Commit)
				}
				if info.Tag != "2024-06-15" {
					t.Errorf("expected tag '2024-06-15', got '%s'", info.Tag)
				}
			},
		},
		{
			name: "repository with multiple tags, returns first one",
			setupRepo: func(t *testing.T, repoDir string) {
				gitDir := filepath.Join(repoDir, ".git")
				if err := os.MkdirAll(gitDir, 0755); err != nil {
					t.Fatal(err)
				}

				commitHash := "111222333444555666777888999aaabbbcccddd"

				// Create detached HEAD
				if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}

				// Create multiple tags pointing to same commit
				refsTags := filepath.Join(gitDir, "refs", "tags")
				if err := os.MkdirAll(refsTags, 0755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(refsTags, "2024-01-01"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(refsTags, "2024-12-31"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, info *Info) {
				if info.Tag == "" {
					t.Error("expected a tag but got empty string")
				}
				// Should return one of the tags (order depends on filesystem)
				if info.Tag != "2024-01-01" && info.Tag != "2024-12-31" {
					t.Errorf("expected tag to be one of the created tags, got '%s'", info.Tag)
				}
			},
		},
		{
			name: "repository without tag for current commit",
			setupRepo: func(t *testing.T, repoDir string) {
				gitDir := filepath.Join(repoDir, ".git")
				if err := os.MkdirAll(gitDir, 0755); err != nil {
					t.Fatal(err)
				}

				commitHash := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

				// Create detached HEAD
				if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(commitHash+"\n"), 0644); err != nil {
					t.Fatal(err)
				}

				// Create tag pointing to different commit
				refsTags := filepath.Join(gitDir, "refs", "tags")
				if err := os.MkdirAll(refsTags, 0755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(refsTags, "2024-06-15"), []byte("0000000000000000000000000000000000000000\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, info *Info) {
				if info.Tag != "" {
					t.Errorf("expected empty tag, got '%s'", info.Tag)
				}
			},
		},
		{
			name: "not a git repository",
			setupRepo: func(t *testing.T, repoDir string) {
				// Don't create .git directory
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tt.setupRepo(t, tmpDir)

			info, err := GetInfo(tmpDir)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, info)
			}
		})
	}
}

func TestFindGitDir(t *testing.T) {
	tests := []struct {
		name        string
		setupRepo   func(t *testing.T, rootDir string)
		expectError bool
		validateDir func(t *testing.T, gitRoot *os.Root, rootDir string)
	}{
		{
			name: ".git directory exists",
			setupRepo: func(t *testing.T, rootDir string) {
				gitDir := filepath.Join(rootDir, ".git")
				if err := os.MkdirAll(gitDir, 0755); err != nil {
					t.Fatal(err)
				}
			},
			expectError: false,
			validateDir: func(t *testing.T, gitRoot *os.Root, rootDir string) {
				expected := filepath.Join(rootDir, ".git")
				if gitRoot.Name() != expected {
					t.Errorf("expected git dir %s, got %s", expected, gitRoot.Name())
				}
			},
		},
		{
			name: ".git directory does not exist",
			setupRepo: func(t *testing.T, rootDir string) {
				// Don't create .git
			},
			expectError: true,
		},
		{
			name: ".git exists but is a file",
			setupRepo: func(t *testing.T, rootDir string) {
				gitFile := filepath.Join(rootDir, ".git")
				if err := os.WriteFile(gitFile, []byte("gitdir: somewhere\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tt.setupRepo(t, tmpDir)

			gitRoot, err := findGitDir(tmpDir)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer gitRoot.Close()

			if tt.validateDir != nil {
				tt.validateDir(t, gitRoot, tmpDir)
			}
		})
	}
}
