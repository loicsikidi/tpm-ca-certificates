package observability

import (
	"context"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// StartSpan creates a new span with the given name and options.
//
// The span should be ended with span.End() when the operation completes,
// typically using defer.
//
// Example:
//
//	ctx, span := observability.StartSpan(ctx, "tpmtb.operation")
//	defer span.End()
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}

// RecordError records an error on the span and sets the status to Error.
//
// This is a convenience function that combines the common pattern of
// recording an error and setting the span status.
//
// Example:
//
//	if err != nil {
//	    observability.RecordError(span, err)
//	    return err
//	}
func RecordError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}
