package apiv1beta

import (
	"context"
	"testing"
)

func TestGetTrustedBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid vendor ID", func(t *testing.T) {
		cfg := GetConfig{
			SkipVerify: true,
			VendorIDs:  []VendorID{"INVALID_VENDOR"},
			AutoUpdate: AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		_, err := GetTrustedBundle(ctx, cfg)
		if err == nil {
			t.Fatal("Expected error for invalid vendor ID")
		}
	})

}
