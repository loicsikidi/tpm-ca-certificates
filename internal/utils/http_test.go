package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Check if context is cancelled or timed out
	if req.Context() != nil {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}
	}
	return m.response, m.err
}

// mockHTTPClientWithAttempts allows configuring different responses per attempt
type mockHTTPClientWithAttempts struct {
	responses []*http.Response
	errors    []error
	attempt   int
	delays    []time.Duration
}

func (m *mockHTTPClientWithAttempts) Do(req *http.Request) (*http.Response, error) {
	// Check if context is cancelled or timed out
	if req.Context() != nil {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}
	}

	// Apply delay if configured for this attempt
	if m.attempt < len(m.delays) && m.delays[m.attempt] > 0 {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(m.delays[m.attempt]):
		}
	}

	idx := m.attempt
	m.attempt++

	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}

	var err error
	if idx < len(m.errors) {
		err = m.errors[idx]
	}

	return m.responses[idx], err
}

func makeResponse(statusCode int, body string, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

func TestHttpGET(t *testing.T) {
	t.Run("successful GET with default max size", func(t *testing.T) {
		expectedBody := "test content"
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, expectedBody, nil),
		}

		data, err := HttpGET(t.Context(), client, "http://example.com/test")
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}
	})

	t.Run("successful GET with custom max size", func(t *testing.T) {
		expectedBody := "small"
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, expectedBody, nil),
		}

		data, err := HttpGET(t.Context(), client, "http://example.com/test", 10)
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}
	})

	t.Run("uses default client when nil", func(t *testing.T) {
		_, err := HttpGET(t.Context(), nil, "http://invalid-url-that-should-fail.local")
		if err == nil {
			t.Fatal("HttpGET() with nil client should fail on invalid URL")
		}
	})

	t.Run("handles non-200 status code", func(t *testing.T) {
		client := &mockHTTPClient{
			response: makeResponse(http.StatusNotFound, "", nil),
		}

		_, err := HttpGET(t.Context(), client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for non-200 status")
		}

		if !errors.Is(err, ErrHTTPGetError) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetError, got %v", err)
		}

		if !strings.Contains(err.Error(), "HTTP 404") {
			t.Errorf("HttpGET() error = %v, want error containing 'HTTP 404'", err)
		}
	})

	t.Run("rejects content exceeding Content-Length header", func(t *testing.T) {
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, "short", map[string]string{
				"Content-Length": "1000",
			}),
		}

		_, err := HttpGET(t.Context(), client, "http://example.com/test", 100)
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for content too large")
		}

		if !errors.Is(err, ErrHTTPGetTooLarge) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetTooLarge, got %v", err)
		}
	})

	t.Run("rejects content exceeding max size without Content-Length header", func(t *testing.T) {
		largeBody := strings.Repeat("a", 101)
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, largeBody, nil),
		}

		_, err := HttpGET(t.Context(), client, "http://example.com/test", 100)
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for content too large")
		}

		if !errors.Is(err, ErrHTTPGetTooLarge) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetTooLarge, got %v", err)
		}
	})

	t.Run("accepts content at exact max size", func(t *testing.T) {
		maxSize := int64(100)
		exactBody := strings.Repeat("a", int(maxSize))
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, exactBody, nil),
		}

		data, err := HttpGET(t.Context(), client, "http://example.com/test", maxSize)
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if int64(len(data)) != maxSize {
			t.Errorf("HttpGET() length = %d, want %d", len(data), maxSize)
		}
	})

	t.Run("handles invalid Content-Length header", func(t *testing.T) {
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, "test", map[string]string{
				"Content-Length": "invalid",
			}),
		}

		_, err := HttpGET(t.Context(), client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for invalid Content-Length")
		}
	})

	t.Run("handles client error", func(t *testing.T) {
		expectedErr := errors.New("network error")
		client := &mockHTTPClient{
			err: expectedErr,
		}

		_, err := HttpGET(t.Context(), client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error")
		}

		if !errors.Is(err, expectedErr) {
			t.Errorf("HttpGET() error = %v, want %v", err, expectedErr)
		}
	})

	t.Run("handles invalid URL", func(t *testing.T) {
		client := &mockHTTPClient{}

		_, err := HttpGET(t.Context(), client, "://invalid-url")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for invalid URL")
		}
	})

	t.Run("handles binary content", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(binaryData)),
			Header:     make(http.Header),
		}
		client := &mockHTTPClient{
			response: resp,
		}

		data, err := HttpGET(t.Context(), client, "http://example.com/binary")
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if len(data) != len(binaryData) {
			t.Fatalf("HttpGET() length = %d, want %d", len(data), len(binaryData))
		}

		for i, b := range binaryData {
			if data[i] != b {
				t.Errorf("HttpGET() data[%d] = 0x%02X, want 0x%02X", i, data[i], b)
			}
		}
	})

	t.Run("ignores additional maxLength parameters beyond first", func(t *testing.T) {
		expectedBody := "test"
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, expectedBody, nil),
		}

		data, err := HttpGET(t.Context(), client, "http://example.com/test", 10, 20, 30)
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}
	})

	t.Run("respects Content-Length when accurate", func(t *testing.T) {
		body := "test content"
		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, body, map[string]string{
				"Content-Length": "12",
			}),
		}

		data, err := HttpGET(t.Context(), client, "http://example.com/test", 100)
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if string(data) != body {
			t.Errorf("HttpGET() = %q, want %q", data, body)
		}
	})

	t.Run("protects against inaccurate Content-Length with LimitReader", func(t *testing.T) {
		// Server claims 5 bytes but sends 105
		largeBody := strings.Repeat("a", 105)
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(largeBody)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Length", "5")

		client := &mockHTTPClient{
			response: resp,
		}

		_, err := HttpGET(t.Context(), client, "http://example.com/test", 100)
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for content exceeding max despite inaccurate Content-Length")
		}

		if !errors.Is(err, ErrHTTPGetTooLarge) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetTooLarge, got %v", err)
		}
	})

	t.Run("respects context timeout", func(t *testing.T) {
		// Create a context with a very short timeout
		ctx, cancel := context.WithTimeout(t.Context(), 1*time.Millisecond)
		defer cancel()

		// Sleep to ensure the context times out
		time.Sleep(10 * time.Millisecond)

		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, "test", nil),
		}

		_, err := HttpGET(ctx, client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for timeout")
		}

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("HttpGET() error = %v, want context.DeadlineExceeded", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		// Create a context and cancel it immediately
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		client := &mockHTTPClient{
			response: makeResponse(http.StatusOK, "test", nil),
		}

		_, err := HttpGET(ctx, client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for cancelled context")
		}

		if !errors.Is(err, context.Canceled) {
			t.Errorf("HttpGET() error = %v, want context.Canceled", err)
		}
	})

	t.Run("retries on 5xx server errors - 504 Gateway Timeout", func(t *testing.T) {
		expectedBody := "success"
		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusOK, expectedBody, nil),
			},
		}

		data, err := HttpGET(context.Background(), client, "http://example.com/test")
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil after retries", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}

		if client.attempt != 3 {
			t.Errorf("Expected 3 attempts, got %d", client.attempt)
		}
	})

	t.Run("retries on 5xx server errors - 500 Internal Server Error", func(t *testing.T) {
		expectedBody := "success"
		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusInternalServerError, "", nil),
				makeResponse(http.StatusInternalServerError, "", nil),
				makeResponse(http.StatusOK, expectedBody, nil),
			},
		}

		data, err := HttpGET(context.Background(), client, "http://example.com/test")
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil after retries", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}

		if client.attempt != 3 {
			t.Errorf("Expected 3 attempts, got %d", client.attempt)
		}
	})

	t.Run("retries on 5xx server errors - 503 Service Unavailable", func(t *testing.T) {
		expectedBody := "success"
		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusServiceUnavailable, "", nil),
				makeResponse(http.StatusOK, expectedBody, nil),
			},
		}

		data, err := HttpGET(context.Background(), client, "http://example.com/test")
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil after retries", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}

		if client.attempt != 2 {
			t.Errorf("Expected 2 attempts, got %d", client.attempt)
		}
	})

	t.Run("fails after max retries on 5xx errors", func(t *testing.T) {
		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusGatewayTimeout, "", nil),
			},
		}

		_, err := HttpGET(context.Background(), client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error after max retries")
		}

		if !errors.Is(err, ErrHTTPGetError) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetError, got %v", err)
		}

		if !strings.Contains(err.Error(), "HTTP 504") {
			t.Errorf("HttpGET() error = %v, want error containing 'HTTP 504'", err)
		}

		// Should attempt 4 times (1 initial + 3 retries)
		if client.attempt != 4 {
			t.Errorf("Expected 4 attempts, got %d", client.attempt)
		}
	})

	t.Run("does not retry on 4xx client errors", func(t *testing.T) {
		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusNotFound, "", nil),
			},
		}

		_, err := HttpGET(context.Background(), client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error")
		}

		if !errors.Is(err, ErrHTTPGetError) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetError, got %v", err)
		}

		// Should only attempt once, no retries for 4xx
		if client.attempt != 1 {
			t.Errorf("Expected 1 attempt, got %d", client.attempt)
		}
	})

	t.Run("context timeout during retry backoff", func(t *testing.T) {
		// Create a context with a timeout shorter than the total retry duration
		// With 3 retries and exponential backoff (100ms, 200ms, 400ms), total would be ~700ms
		// Set timeout to 50ms to ensure it times out during first backoff
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusOK, "success", nil),
			},
		}

		_, err := HttpGET(ctx, client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for timeout during retry")
		}

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("HttpGET() error = %v, want context.DeadlineExceeded", err)
		}

		// Should have attempted at least once before timeout
		if client.attempt < 1 {
			t.Errorf("Expected at least 1 attempt, got %d", client.attempt)
		}
	})

	t.Run("exponential backoff timing with 5xx errors", func(t *testing.T) {
		// Save original config and restore after test
		originalRandomization := DefaultBackoffConfig.RandomizationFactor
		defer func() {
			DefaultBackoffConfig.RandomizationFactor = originalRandomization
		}()

		// Disable randomization for predictable timing
		DefaultBackoffConfig.RandomizationFactor = 0

		client := &mockHTTPClientWithAttempts{
			responses: []*http.Response{
				makeResponse(http.StatusGatewayTimeout, "", nil),
				makeResponse(http.StatusInternalServerError, "", nil),
				makeResponse(http.StatusServiceUnavailable, "", nil),
				makeResponse(http.StatusOK, "success", nil),
			},
		}

		start := time.Now()
		_, err := HttpGET(context.Background(), client, "http://example.com/test")
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil after retries", err)
		}

		// Expected backoff: 100ms + 200ms + 400ms = 700ms minimum
		// Allow some margin for execution time
		expectedMin := 700 * time.Millisecond
		expectedMax := 1000 * time.Millisecond

		if elapsed < expectedMin {
			t.Errorf("HttpGET() completed too quickly: %v, expected at least %v", elapsed, expectedMin)
		}

		if elapsed > expectedMax {
			t.Errorf("HttpGET() took too long: %v, expected at most %v", elapsed, expectedMax)
		}

		if client.attempt != 4 {
			t.Errorf("Expected 4 attempts, got %d", client.attempt)
		}
	})
}
