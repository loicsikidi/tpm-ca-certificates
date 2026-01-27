package main

import (
	"context"
	"os"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/observability"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdown, err := observability.Initialize(ctx, observability.Config{
		Enabled: true,
		Sampler: observability.AlwaysOnSample,
	})
	if err != nil {
		cli.DisplayError("Failed to initialize tracing: %v", err)
		os.Exit(1)
	}

	defer func() {
		if err := observability.Shutdown(shutdown); err != nil {
			cli.DisplayWarning("Failed to shutdown tracing: %v", err)
		}
	}()

	cacheDir := os.TempDir()
	for range 2 {
		_, err := apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{
			CachePath: cacheDir,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		})
		if err != nil {
			cli.DisplayError("Failed to get trusted bundle: %v", err)
			os.Exit(1)
		}
	}
	cli.DisplaySuccess("Finished!")
}
