package observability

import (
	"fmt"
	"os"
	"slices"
	"strconv"
)

const (
	defaultEndpoint    = "localhost:4317"
	defaultServiceName = "tpmtb"
	defaultSampler     = AlwaysOnSample
)

const (
	AlwaysOnSample     = "always_on"
	AlwaysOffSample    = "always_off"
	TraceIDRatioSample = "traceidratio"
)

var validSamplers = []string{
	AlwaysOnSample,
	AlwaysOffSample,
	TraceIDRatioSample,
}

// Config configures OpenTelemetry tracing.
type Config struct {
	// Endpoint is the OTLP gRPC endpoint (e.g., "localhost:4317").
	//
	// Optional. Defaults to "localhost:4317" if not set.
	// Can be overridden via OTEL_EXPORTER_OTLP_ENDPOINT environment variable.
	Endpoint string

	// ServiceName is the name of the service in traces.
	//
	// Optional. Defaults to "tpmtb" if not set.
	// Can be overridden via OTEL_SERVICE_NAME environment variable.
	ServiceName string

	// Sampler determines which traces to sample.
	//
	// Optional. Defaults to "always_on" if not set.
	// Can be overridden via OTEL_TRACES_SAMPLER environment variable.
	// Valid values: "always_on", "always_off", "traceidratio"
	Sampler string

	// Enabled enables tracing.
	//
	// Optional. Defaults to false (tracing disabled).
	// Can be overridden via OTEL_ENABLED environment variable.
	Enabled bool
}

// CheckAndSetDefaults validates and sets default values.
//
// Environment variables take precedence over struct fields.
func (c *Config) CheckAndSetDefaults() error {
	if enabledStr := os.Getenv("OTEL_ENABLED"); enabledStr != "" {
		enabled, err := strconv.ParseBool(enabledStr)
		if err != nil {
			return fmt.Errorf("invalid OTEL_ENABLED value: %w", err)
		}
		c.Enabled = enabled
	}

	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		c.Endpoint = endpoint
	}
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint
	}

	if serviceName := os.Getenv("OTEL_SERVICE_NAME"); serviceName != "" {
		c.ServiceName = serviceName
	}
	if c.ServiceName == "" {
		c.ServiceName = defaultServiceName
	}

	if sampler := os.Getenv("OTEL_TRACES_SAMPLER"); sampler != "" {
		c.Sampler = sampler
	}
	if c.Sampler == "" {
		c.Sampler = defaultSampler
	}

	if !slices.Contains(validSamplers, c.Sampler) {
		return fmt.Errorf("invalid sampler: %s (must be one of %v)", c.Sampler, validSamplers)
	}

	return nil
}
