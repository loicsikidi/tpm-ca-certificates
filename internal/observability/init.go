package observability

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const tracerName = "github.com/loicsikidi/tpm-ca-certificates"

// ShutdownFunc is a function that shuts down the tracing provider.
type ShutdownFunc func(context.Context) error

var (
	// NoOpShutdownFunc is a no-op shutdown function that does nothing.
	NoOpShutdownFunc = func(context.Context) error { return nil }

	// globalTracerProvider holds the configured tracer provider.
	// It's either a real TracerProvider or noop.NewTracerProvider().
	globalTracerProvider trace.TracerProvider = noop.NewTracerProvider()

	// initOnce ensures Initialize is only called once.
	initOnce sync.Once

	// initErr stores any error from the initialization.
	initErr error

	// initShutdown stores the shutdown function from initialization.
	initShutdown ShutdownFunc
)

// Initialize sets up OpenTelemetry tracing with OTLP gRPC exporter.
//
// It configures a [sdktrace.TracerProvider] and registers it globally. Returns a shutdown
// function that MUST be called before program exit to ensure all spans are exported.
//
// This function is thread-safe and can only be called once. Subsequent calls will return
// the result of the first call (either success or error).
//
// If cfg.Enabled is false (default), this function returns immediately with a no-op
// shutdown function, allowing the application to run without any tracing overhead.
//
// If the OTLP endpoint is unreachable or initialization fails,
// this function returns an error. The caller should handle this gracefully (e.g., log
// a warning but continue execution).
//
// Example:
//
//	cfg := observability.Config{}
//	shutdown, err := observability.Initialize(context.Background(), cfg)
//	if err != nil {
//	    log.Printf("Warning: Failed to initialize tracing: %v", err)
//	}
//	defer shutdown(context.Background())
func Initialize(ctx context.Context, optionalCfg ...Config) (ShutdownFunc, error) {
	initOnce.Do(func() {
		cfg := utils.OptionalArg(optionalCfg)
		initShutdown, initErr = initialize(ctx, cfg)
	})

	return initShutdown, initErr
}

func initialize(ctx context.Context, cfg Config) (ShutdownFunc, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid observability config: %w", err)
	}

	if !cfg.Enabled {
		return NoOpShutdownFunc, nil
	}

	defaultOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(),
	}

	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		defaultOpts = append(defaultOpts, otlptracegrpc.WithTimeout(5*time.Second))
	}

	exporter, err := otlptracegrpc.New(ctx, defaultOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create TracerProvider with batching for performance
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(createSampler(cfg.Sampler)),
	)

	globalTracerProvider = tp

	// Register globally so library code can use otel.GetTracerProvider()
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

func createSampler(samplerType string) sdktrace.Sampler {
	switch samplerType {
	case AlwaysOffSample:
		return sdktrace.NeverSample()
	case TraceIDRatioSample:
		// Default to 0.1 (10% sampling) for traceidratio
		return sdktrace.TraceIDRatioBased(0.1)
	default: // "always_on"
		return sdktrace.AlwaysSample()
	}
}

// Tracer returns a tracer for creating spans.
func Tracer() trace.Tracer {
	return globalTracerProvider.Tracer(tracerName)
}
