package observability

import (
	"testing"
)

func TestConfig_CheckAndSetDefaults(t *testing.T) {
	t.Run("uses default values", func(t *testing.T) {
		cfg := Config{}
		if err := cfg.CheckAndSetDefaults(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Endpoint != defaultEndpoint {
			t.Errorf("expected endpoint %s, got %s", defaultEndpoint, cfg.Endpoint)
		}
		if cfg.ServiceName != defaultServiceName {
			t.Errorf("expected service name %s, got %s", defaultServiceName, cfg.ServiceName)
		}
		if cfg.Sampler != defaultSampler {
			t.Errorf("expected sampler %s, got %s", defaultSampler, cfg.Sampler)
		}
		if cfg.Enabled {
			t.Error("expected Enabled to be false by default")
		}
	})

	t.Run("uses environment variables", func(t *testing.T) {
		t.Setenv("OTEL_ENABLED", "true")
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "custom:1234")
		t.Setenv("OTEL_SERVICE_NAME", "my-service")
		t.Setenv("OTEL_TRACES_SAMPLER", "always_off")

		cfg := Config{}
		if err := cfg.CheckAndSetDefaults(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !cfg.Enabled {
			t.Error("expected Enabled to be true from env var")
		}
		if cfg.Endpoint != "custom:1234" {
			t.Errorf("expected endpoint custom:1234, got %s", cfg.Endpoint)
		}
		if cfg.ServiceName != "my-service" {
			t.Errorf("expected service name my-service, got %s", cfg.ServiceName)
		}
		if cfg.Sampler != "always_off" {
			t.Errorf("expected sampler always_off, got %s", cfg.Sampler)
		}
	})

	t.Run("environment variables override struct values", func(t *testing.T) {
		t.Setenv("OTEL_ENABLED", "true")
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "env:9999")

		cfg := Config{
			Enabled:  false, // should be overridden
			Endpoint: "struct:8888",
		}
		if err := cfg.CheckAndSetDefaults(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !cfg.Enabled {
			t.Error("expected env var to override Enabled field")
		}
		if cfg.Endpoint != "env:9999" {
			t.Errorf("expected env var to override endpoint, got %s", cfg.Endpoint)
		}
	})

	t.Run("validates sampler values", func(t *testing.T) {
		testCases := []struct {
			name    string
			sampler string
			wantErr bool
		}{
			{"always_on is valid", "always_on", false},
			{"always_off is valid", "always_off", false},
			{"traceidratio is valid", "traceidratio", false},
			{"invalid sampler", "invalid", true},
			{"empty sampler defaults to always_on", "", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := Config{Sampler: tc.sampler}
				err := cfg.CheckAndSetDefaults()

				if tc.wantErr && err == nil {
					t.Error("expected error for invalid sampler")
				}
				if !tc.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("handles invalid OTEL_ENABLED value", func(t *testing.T) {
		t.Setenv("OTEL_ENABLED", "not-a-bool")

		cfg := Config{}
		err := cfg.CheckAndSetDefaults()
		if err == nil {
			t.Fatal("expected error for invalid OTEL_ENABLED value")
		}
	})
}
