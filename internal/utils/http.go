package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
)

var (
	ErrHTTPGetTooLarge = fmt.Errorf("downloaded content exceeds maximum allowed size")
	ErrHTTPGetError    = fmt.Errorf("error during HTTP GET request")
)

const (
	maxRetries = 4 // Total attempts: 1 initial + 3 retries
)

// DefaultBackoffConfig holds the default exponential backoff configuration for HTTP retries.
// Can be modified for testing purposes.
var DefaultBackoffConfig = &backoff.ExponentialBackOff{
	InitialInterval:     100 * time.Millisecond,
	MaxInterval:         500 * time.Millisecond,
	Multiplier:          2.0, // Double the interval each retry
	RandomizationFactor: 0.5, // Default randomization factor (±50%)
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func HttpGET(ctx context.Context, client HTTPClient, url string, optionalMaxLength ...int64) ([]byte, error) {
	maxLength := OptionalArgWithDefault(optionalMaxLength, DefaultMaxFileSize)
	c := client
	if c == nil {
		c = http.DefaultClient
	}

	expBackoff := &backoff.ExponentialBackOff{
		InitialInterval:     DefaultBackoffConfig.InitialInterval,
		MaxInterval:         DefaultBackoffConfig.MaxInterval,
		Multiplier:          DefaultBackoffConfig.Multiplier,
		RandomizationFactor: DefaultBackoffConfig.RandomizationFactor,
	}

	operation := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, backoff.Permanent(err)
		}

		res, err := c.Do(req)
		if err != nil {
			return nil, backoff.Permanent(err)
		}

		if res.StatusCode >= 500 && res.StatusCode < 600 {
			res.Body.Close()
			return nil, fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
		}

		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			err := fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
			return nil, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetError, err))
		}

		// Process successful response
		var length int64
		if header := res.Header.Get("Content-Length"); header != "" {
			length, err = strconv.ParseInt(header, 10, 0)
			if err != nil {
				res.Body.Close()
				return nil, backoff.Permanent(err)
			}
			if length > maxLength {
				res.Body.Close()
				err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, length, maxLength)
				return nil, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err))
			}
		}

		// Although the size has been checked above, use a LimitReader in case
		// the reported size is inaccurate.
		data, err := io.ReadAll(io.LimitReader(res.Body, maxLength+1))
		res.Body.Close()
		if err != nil {
			return nil, backoff.Permanent(err)
		}

		length = int64(len(data))
		if int64(length) > maxLength {
			err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, length, maxLength)
			return nil, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err))
		}
		return data, nil
	}

	data, err := backoff.Retry(ctx, operation, backoff.WithBackOff(expBackoff), backoff.WithMaxTries(maxRetries))
	if err != nil {
		// backoff.Retry automatically unwraps permanent errors
		// So errors here are either:
		// 1. Already unwrapped permanent errors (client errors, ErrHTTPGetError, ErrHTTPGetTooLarge)
		// 2. Context errors (canceled, deadline exceeded)
		// 3. Retryable errors that exhausted max retries (5xx server errors)

		// Return context errors directly
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		// Return errors already wrapped with sentinel errors
		if errors.Is(err, ErrHTTPGetError) || errors.Is(err, ErrHTTPGetTooLarge) {
			return nil, err
		}

		// Check if this is a retryable 5xx error that exhausted retries
		// These need to be wrapped with ErrHTTPGetError
		errMsg := err.Error()
		for code := 500; code < 600; code++ {
			if strings.Contains(errMsg, "HTTP "+strconv.Itoa(code)) {
				return nil, fmt.Errorf("%w: %v", ErrHTTPGetError, err)
			}
		}

		// All other errors (client, network, etc.) return as-is
		return nil, err
	}

	return data, nil
}
