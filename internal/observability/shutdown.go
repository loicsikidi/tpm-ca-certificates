package observability

import (
	"context"
	"time"
)

// Shutdown gracefully shuts down the tracing provider with a timeout.
//
// This wrapper ensures spans are flushed before exit and provides a
// sensible timeout to prevent hanging on shutdown.
//
// Example:
//
//	defer observability.Shutdown(shutdown)
func Shutdown(shutdownFunc ShutdownFunc) error {
	if shutdownFunc == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return shutdownFunc(ctx)
}
