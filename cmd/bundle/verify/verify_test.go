package verify

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/spf13/cobra"
)

func TestRunOfflineMode(t *testing.T) {
	cacheConfig := apiv1beta.CacheConfig{
		Version:       testutil.BundleVersion,
		SkipVerify:    false,
		LastTimestamp: time.Now(),
		AutoUpdate: &apiv1beta.AutoUpdateConfig{
			DisableAutoUpdate: true,
		},
	}
	cacheConfigData, err := json.Marshal(cacheConfig)
	if err != nil {
		t.Fatalf("Failed to marshal cache config: %v", err)
	}

	// Create a complete cache directory using testutil
	cacheDir := testutil.CreateCacheDir(t, cacheConfigData)

	tests := []struct {
		name    string
		opts    *Opts
		args    []string
		wantErr bool
	}{
		{
			name: "offline mode with valid cache",
			opts: &Opts{
				CacheDir: cacheDir,
				Offline:  true,
			},
			args:    []string{cacheDir + "/" + testutil.RootBundleFile},
			wantErr: false,
		},
		{
			name: "offline mode with non-existent cache dir",
			opts: &Opts{
				CacheDir: "/nonexistent/path",
				Offline:  true,
			},
			args:    []string{cacheDir + "/" + testutil.RootBundleFile},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetContext(t.Context())

			err := run(cmd, tt.args, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunWithCacheDir(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Opts
		wantErr bool
	}{
		{
			name: "non-existent cache directory with offline mode",
			opts: &Opts{
				CacheDir: "/nonexistent/path",
				Offline:  true,
			},
			wantErr: true,
		},
		{
			name: "non-existent cache directory without offline mode",
			opts: &Opts{
				CacheDir: "/nonexistent/path",
				Offline:  false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create cache config
			cacheConfig := apiv1beta.CacheConfig{
				Version:       testutil.BundleVersion,
				SkipVerify:    false,
				LastTimestamp: time.Now(),
				AutoUpdate: &apiv1beta.AutoUpdateConfig{
					DisableAutoUpdate: true,
				},
			}
			cacheConfigData, err := json.Marshal(cacheConfig)
			if err != nil {
				t.Fatalf("Failed to marshal cache config: %v", err)
			}

			// Create a complete cache directory using testutil
			cacheDir := testutil.CreateCacheDir(t, cacheConfigData)

			cmd := &cobra.Command{}
			cmd.SetContext(t.Context())

			args := []string{cacheDir + "/" + testutil.RootBundleFile}
			err = run(cmd, args, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
