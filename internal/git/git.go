package git

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Info contains Git repository information.
type Info struct {
	Commit string // Full commit hash (40 characters)
	Branch string // Current branch name
	Tag    string // Tag pointing to current commit (if any)
}

// GetInfo retrieves Git information from the repository containing the given path.
// It reads .git/HEAD and .git/refs to determine the current commit, branch, and tag
// without using external dependencies.
//
// Example:
//
//	info, err := git.GetInfo(".")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Commit: %s\n", info.Commit)
//	fmt.Printf("Branch: %s\n", info.Branch)
//	fmt.Printf("Tag: %s\n", info.Tag)
func GetInfo(repoPath string) (*Info, error) {
	gitRoot, err := findGitDir(repoPath)
	if err != nil {
		return nil, err
	}
	defer gitRoot.Close()

	headContent, err := fs.ReadFile(gitRoot.FS(), "HEAD")
	if err != nil {
		return nil, fmt.Errorf("failed to read HEAD: %w", err)
	}

	head := strings.TrimSpace(string(headContent))

	var commitHash string
	var branch string

	// Check if HEAD points to a ref (branch) or is detached (direct commit hash)
	if after, ok := strings.CutPrefix(head, "ref: "); ok {
		// HEAD points to a branch ref
		ref := after

		commitBytes, err := fs.ReadFile(gitRoot.FS(), ref)
		if err != nil {
			return nil, fmt.Errorf("failed to read ref %s: %w", ref, err)
		}

		commitHash = strings.TrimSpace(string(commitBytes))

		if after, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
			branch = after
		}
	} else {
		// HEAD is detached (direct commit hash)
		commitHash = head
	}

	// Find tag pointing to current commit
	tag, err := findTagForCommit(gitRoot, commitHash)
	if err != nil {
		// Tag lookup failure is not fatal, just leave it empty
		tag = ""
	}

	return &Info{
		Commit: commitHash,
		Branch: branch,
		Tag:    tag,
	}, nil
}

// findGitDir locates the .git directory in the given path and returns a scoped Root.
// The caller is responsible for closing the returned Root.
func findGitDir(dir string) (*os.Root, error) {
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	root, err := os.OpenRoot(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory: %w", err)
	}

	info, err := root.Stat(".git")
	if err != nil {
		root.Close()
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not a git repository")
		}
		return nil, fmt.Errorf("failed to stat .git: %w", err)
	}

	if !info.IsDir() {
		root.Close()
		return nil, fmt.Errorf(".git exists but is not a directory")
	}

	// Open the .git directory itself as a Root
	gitRoot, err := os.OpenRoot(filepath.Join(absPath, ".git"))
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("failed to open .git directory: %w", err)
	}
	root.Close()

	return gitRoot, nil
}

// findTagForCommit searches for a tag pointing to the given commit hash.
// It reads all files in .git/refs/tags/ and returns the first tag that points to the commit.
// Returns empty string if no tag is found.
func findTagForCommit(gitRoot *os.Root, commitHash string) (string, error) {
	tagsPath := filepath.Join("refs", "tags")

	if _, err := gitRoot.Stat(tagsPath); os.IsNotExist(err) {
		return "", nil
	}

	entries, err := fs.ReadDir(gitRoot.FS(), tagsPath)
	if err != nil {
		return "", fmt.Errorf("failed to read tags directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		tagFilePath := filepath.Join(tagsPath, entry.Name())
		tagCommit, err := fs.ReadFile(gitRoot.FS(), tagFilePath)
		if err != nil {
			continue
		}

		if strings.TrimSpace(string(tagCommit)) == commitHash {
			return entry.Name(), nil
		}
	}

	return "", nil
}
