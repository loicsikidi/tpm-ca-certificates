package cache

import (
	"os"
	"path/filepath"
	"sync"
)

const (
	// CacheDirName is the default folder name for tpmtb cache.
	CacheDirName = ".tpmtb"
)

var (
	once sync.Once
	path string
)

// CacheDir returns the path to the cache directory.
//
// It initializes the path on the first call by determining the user's home directory
func CacheDir() string {
	once.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			// Fall back to using a tpmtb repository in the temp location
			home = os.TempDir()
		}
		path = filepath.Join(home, CacheDirName)
	})
	return path
}
