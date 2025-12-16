package utils

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
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

		data, err := HttpGET(client, "http://example.com/test")
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

		data, err := HttpGET(client, "http://example.com/test", 10)
		if err != nil {
			t.Fatalf("HttpGET() error = %v, want nil", err)
		}

		if string(data) != expectedBody {
			t.Errorf("HttpGET() = %q, want %q", data, expectedBody)
		}
	})

	t.Run("uses default client when nil", func(t *testing.T) {
		_, err := HttpGET(nil, "http://invalid-url-that-should-fail.local")
		if err == nil {
			t.Fatal("HttpGET() with nil client should fail on invalid URL")
		}
	})

	t.Run("handles non-200 status code", func(t *testing.T) {
		client := &mockHTTPClient{
			response: makeResponse(http.StatusNotFound, "", nil),
		}

		_, err := HttpGET(client, "http://example.com/test")
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

		_, err := HttpGET(client, "http://example.com/test", 100)
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

		_, err := HttpGET(client, "http://example.com/test", 100)
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

		data, err := HttpGET(client, "http://example.com/test", maxSize)
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

		_, err := HttpGET(client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for invalid Content-Length")
		}
	})

	t.Run("handles client error", func(t *testing.T) {
		expectedErr := errors.New("network error")
		client := &mockHTTPClient{
			err: expectedErr,
		}

		_, err := HttpGET(client, "http://example.com/test")
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error")
		}

		if !errors.Is(err, expectedErr) {
			t.Errorf("HttpGET() error = %v, want %v", err, expectedErr)
		}
	})

	t.Run("handles invalid URL", func(t *testing.T) {
		client := &mockHTTPClient{}

		_, err := HttpGET(client, "://invalid-url")
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

		data, err := HttpGET(client, "http://example.com/binary")
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

		data, err := HttpGET(client, "http://example.com/test", 10, 20, 30)
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

		data, err := HttpGET(client, "http://example.com/test", 100)
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

		_, err := HttpGET(client, "http://example.com/test", 100)
		if err == nil {
			t.Fatal("HttpGET() error = nil, want error for content exceeding max despite inaccurate Content-Length")
		}

		if !errors.Is(err, ErrHTTPGetTooLarge) {
			t.Errorf("HttpGET() error should wrap ErrHTTPGetTooLarge, got %v", err)
		}
	})
}
