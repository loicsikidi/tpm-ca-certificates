package internal

import (
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"go.yaml.in/yaml/v4"
)

func TestGenerate(t *testing.T) {
	t.Run("deterministic generation", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping deterministic generation test in short mode")
		}

		// Load test config
		configData, err := testutil.ReadTestFile(testutil.ConfigFile)
		if err != nil {
			t.Fatalf("Failed to read test config: %v", err)
		}

		var cfg config.TPMRootsConfig
		if err := yaml.Unmarshal(configData, &cfg); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		gen := bundle.NewGenerator()

		// Generate bundle 10 times with different worker counts
		const iterations = 10
		bundles := make([]string, iterations)

		for i := range iterations {
			bundle, err := gen.GenerateWithMetadata(&cfg, 10, "", "2025-01-01", "abc123")
			if err != nil {
				t.Fatalf("Generate() iteration %d error = %v", i+1, err)
			}
			bundles[i] = bundle
		}

		// Verify all generations produce identical output
		reference := bundles[0]
		for i := 1; i < iterations; i++ {
			if bundles[i] != reference {
				t.Errorf("Generation %d differs from reference (generation 1)", i+1)
				t.Logf("Reference length: %d, Generation %d length: %d", len(reference), i+1, len(bundles[i]))
			}
		}
	})
}
