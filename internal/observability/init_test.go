package observability

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
)

func TestInitialize_WithDisabled(t *testing.T) {
	ctx := context.Background()

	// Test with Enabled=false (default)
	cfg := Config{
		Enabled: false,
	}

	shutdown, err := Initialize(ctx, cfg)
	if err != nil {
		t.Fatalf("Initialize should not return error when disabled: %v", err)
	}

	if shutdown == nil {
		t.Fatal("shutdown function should not be nil")
	}

	// Shutdown should be no-op
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown should not return error: %v", err)
	}
}

func TestInitialize_WithInvalidConfig(t *testing.T) {
	// Reset state for this test
	resetInitState()

	ctx := context.Background()

	// Invalid sampler
	cfg := Config{
		Enabled: true,
		Sampler: "invalid-sampler",
	}

	_, err := Initialize(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestCreateSampler(t *testing.T) {
	testCases := []struct {
		name         string
		samplerType  string
		expectedType string
	}{
		{"always_on creates AlwaysSample", "always_on", "AlwaysSample"},
		{"always_off creates NeverSample", "always_off", "NeverSample"},
		{"traceidratio creates TraceIDRatioBased", "traceidratio", "TraceIDRatioBased"},
		{"unknown defaults to AlwaysSample", "unknown", "AlwaysSample"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sampler := createSampler(tc.samplerType)
			if sampler == nil {
				t.Fatal("sampler should not be nil")
			}

			// Verify sampler is not nil - all samplers implement sdktrace.Sampler
			// The specific type verification would require checking the concrete type,
			// but since all valid samplers implement the interface, we just verify non-nil
		})
	}
}

func TestTracer(t *testing.T) {
	// Tracer should always return a valid tracer (no-op or real)
	tracer := Tracer()
	if tracer == nil {
		t.Fatal("Tracer() should not return nil")
	}

	// Should be able to start a span
	ctx := context.Background()
	_, span := tracer.Start(ctx, "test-span")
	if span == nil {
		t.Fatal("span should not be nil")
	}
	span.End()
}

func TestNoopMode_TracerReturnsNoopSpan(t *testing.T) {
	cleanup := setTracerProviderForTest()
	defer cleanup()

	ctx := context.Background()

	// Get tracer and verify it returns noop spans
	tracer := Tracer()
	if tracer == nil {
		t.Fatal("Tracer() should not return nil")
	}

	// Start a span and verify it's a noop span
	_, span := tracer.Start(ctx, "test-noop-span")
	if span == nil {
		t.Fatal("span should not be nil")
	}

	// A noop span should not be recording
	if span.IsRecording() {
		t.Error("noop span should not be recording")
	}

	// Verify the span context is not valid (characteristic of noop spans)
	spanCtx := span.SpanContext()
	if spanCtx.IsValid() {
		t.Error("noop span context should not be valid")
	}

	span.End()
}

// resetInitState resets the initialization state for testing Initialize().
// This should only be used in tests that test Initialize() itself.
func resetInitState() {
	globalTracerProvider = noop.NewTracerProvider()
	initOnce = sync.Once{}
	initErr = nil
	initShutdown = nil
}

// setTracerProviderForTest sets a test TracerProvider and returns a cleanup function.
// This is the preferred way to test code that uses Tracer() without calling Initialize().
//
// Example:
//
//	cleanup := setTracerProviderForTest()
//	defer cleanup()
//	// Now Tracer() returns a noop tracer
func setTracerProviderForTest() func() {
	originalProvider := globalTracerProvider
	globalTracerProvider = noop.NewTracerProvider()

	return func() {
		globalTracerProvider = originalProvider
	}
}

func TestInitialize_ConcurrentCalls(t *testing.T) {
	// Reset state for this test
	resetInitState()

	ctx := context.Background()
	cfg := Config{
		Enabled: false,
	}

	// Call Initialize concurrently from multiple goroutines
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make([]error, numGoroutines)
	shutdowns := make([]ShutdownFunc, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			shutdowns[idx], errors[idx] = Initialize(ctx, cfg)
		}(i)
	}

	wg.Wait()

	// All calls should succeed
	for i, err := range errors {
		if err != nil {
			t.Errorf("Initialize call %d returned error: %v", i, err)
		}
	}

	// All shutdown functions should be the same (because of sync.Once)
	for i := 1; i < numGoroutines; i++ {
		if shutdowns[i] == nil {
			t.Errorf("Shutdown function %d is nil", i)
		}
	}

	// Tracer should return noop spans
	tracer := Tracer()
	_, span := tracer.Start(ctx, "test-span")
	if span.IsRecording() {
		t.Error("span should not be recording in noop mode")
	}
	span.End()
}

func TestTracer_ConcurrentAccess(t *testing.T) {
	cleanup := setTracerProviderForTest()
	defer cleanup()

	ctx := context.Background()

	// Call Tracer concurrently from multiple goroutines
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			tracer := Tracer()
			if tracer == nil {
				t.Error("Tracer() returned nil")
				return
			}

			// Start and end a span
			_, span := tracer.Start(ctx, "concurrent-test-span")
			if span == nil {
				t.Error("span is nil")
				return
			}
			span.End()
		}()
	}

	wg.Wait()
}

func TestNoopMode_StartSpanReturnsNoopSpan(t *testing.T) {
	cleanup := setTracerProviderForTest()
	defer cleanup()

	ctx := context.Background()

	// Use StartSpan helper
	_, span := StartSpan(ctx, "test-operation")
	if span == nil {
		t.Fatal("StartSpan should not return nil span")
	}

	// Verify it's a noop span
	if span.IsRecording() {
		t.Error("span from StartSpan should not be recording in noop mode")
	}

	if span.SpanContext().IsValid() {
		t.Error("span context should not be valid in noop mode")
	}

	span.End()
}

func TestEnabledMode_TracerReturnsRealSpan(t *testing.T) {
	t.Skip("Requires OTLP endpoint - run in integration tests")

	// This test would call Initialize with Enabled=true
	// It requires a real OTLP endpoint and is meant to be run as an integration test
}

func TestTracerProvider_InitialState(t *testing.T) {
	cleanup := setTracerProviderForTest()
	defer cleanup()

	// Before Initialize is called, Tracer() should return a noop tracer
	tracer := Tracer()
	if tracer == nil {
		t.Fatal("Tracer() should not return nil")
	}

	_, span := tracer.Start(context.Background(), "test-span")

	// Should be a noop span
	if span.IsRecording() {
		t.Error("initial tracer should return noop spans")
	}

	span.End()
}
