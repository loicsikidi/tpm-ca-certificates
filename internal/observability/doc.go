// Package observability provides OpenTelemetry tracing instrumentation for tpmtb.
//
// It initializes an OTLP gRPC exporter and provides helpers for creating spans.
// Configuration is done via [Config] struct or environment variables.
//
// # Tracing is disabled by default
//
// To enable tracing, set the OTEL_ENABLED environment variable to "true":
//
//	export OTEL_ENABLED=true
//
// # Environment Variables
//
//   - OTEL_ENABLED: Enable tracing (default: false)
//   - OTEL_EXPORTER_OTLP_ENDPOINT: OTLP gRPC endpoint (default: localhost:4317)
//   - OTEL_SERVICE_NAME: Service name in traces (default: tpmtb)
//   - OTEL_TRACES_SAMPLER: Sampling strategy (default: always_on)
//     Valid values: always_on, always_off, traceidratio
//
// # Example
//
//	cfg := observability.Config{}
//	shutdown, err := observability.Initialize(context.Background(), cfg)
//	if err != nil {
//	    log.Printf("Failed to initialize tracing: %v", err)
//	}
//	defer observability.Shutdown(shutdown)
package observability
