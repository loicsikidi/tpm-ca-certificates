package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSResolver_Fetch(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		expectedData := "certificate data"
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(expectedData))
		}))
		defer server.Close()

		resolver := NewHTTPSResolver(server.URL, server.Client())
		data, err := resolver.Fetch(context.Background())

		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil", err)
		}

		if string(data) != expectedData {
			t.Errorf("Fetch() = %q, want %q", data, expectedData)
		}
	})

	t.Run("handles HTTP 404 error", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		resolver := NewHTTPSResolver(server.URL, server.Client())
		_, err := resolver.Fetch(context.Background())

		if err == nil {
			t.Fatal("Fetch() error = nil, want error")
		}

		if !strings.Contains(err.Error(), "failed to download from") {
			t.Errorf("Fetch() error = %v, want error containing 'failed to download from'", err)
		}
	})

	t.Run("handles HTTP 500 error", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		resolver := NewHTTPSResolver(server.URL, server.Client())
		_, err := resolver.Fetch(context.Background())

		if err == nil {
			t.Fatal("Fetch() error = nil, want error")
		}

		if !strings.Contains(err.Error(), "failed to download from") {
			t.Errorf("Fetch() error = %v, want error containing 'failed to download from'", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		resolver := NewHTTPSResolver(server.URL, server.Client())
		_, err := resolver.Fetch(ctx)

		if err == nil {
			t.Fatal("Fetch() error = nil, want error for cancelled context")
		}
	})

	t.Run("handles large response", func(t *testing.T) {
		largeData := strings.Repeat("a", 1000)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(largeData))
		}))
		defer server.Close()

		resolver := NewHTTPSResolver(server.URL, server.Client())
		data, err := resolver.Fetch(context.Background())

		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil", err)
		}

		if len(data) != len(largeData) {
			t.Errorf("Fetch() length = %d, want %d", len(data), len(largeData))
		}
	})
}

func TestNewFileResolver(t *testing.T) {
	t.Run("creates file resolver with absolute path", func(t *testing.T) {
		absPath := "/home/user/cert.pem"

		resolver, err := NewFileResolver(absPath)

		if err != nil {
			t.Fatalf("NewFileResolver() error = %v, want nil", err)
		}

		if resolver.path != absPath {
			t.Errorf("NewFileResolver() path = %q, want %q", resolver.path, absPath)
		}
	})

	t.Run("creates file resolver with file:// prefix", func(t *testing.T) {
		absPath := "/home/user/cert.pem"
		uri := "file://" + absPath

		resolver, err := NewFileResolver(uri)

		if err != nil {
			t.Fatalf("NewFileResolver() error = %v, want nil", err)
		}

		if resolver.path != absPath {
			t.Errorf("NewFileResolver() path = %q, want %q", resolver.path, absPath)
		}
	})

	t.Run("rejects relative path", func(t *testing.T) {
		relativePath := "certs/cert.pem"

		_, err := NewFileResolver(relativePath)

		if err == nil {
			t.Fatal("NewFileResolver() error = nil, want error for relative path")
		}

		if !strings.Contains(err.Error(), "relative paths are not supported") {
			t.Errorf("NewFileResolver() error = %v, want error containing 'relative paths are not supported'", err)
		}
	})

	t.Run("rejects relative path with file:// prefix", func(t *testing.T) {
		relativePath := "file://certs/cert.pem"

		_, err := NewFileResolver(relativePath)

		if err == nil {
			t.Fatal("NewFileResolver() error = nil, want error for relative path")
		}

		if !strings.Contains(err.Error(), "relative paths are not supported") {
			t.Errorf("NewFileResolver() error = %v, want error containing 'relative paths are not supported'", err)
		}
	})
}

func TestFileResolver_Fetch(t *testing.T) {
	t.Run("reads file successfully", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.pem")
		expectedData := "certificate content"

		if err := os.WriteFile(testFile, []byte(expectedData), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		resolver, err := NewFileResolver(testFile)
		if err != nil {
			t.Fatalf("NewFileResolver() error = %v, want nil", err)
		}

		data, err := resolver.Fetch(context.Background())

		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil", err)
		}

		if string(data) != expectedData {
			t.Errorf("Fetch() = %q, want %q", data, expectedData)
		}
	})

	t.Run("handles non-existent file", func(t *testing.T) {
		nonExistentPath := "/tmp/non-existent-file-12345.pem"

		resolver, err := NewFileResolver(nonExistentPath)
		if err != nil {
			t.Fatalf("NewFileResolver() error = %v, want nil", err)
		}

		_, err = resolver.Fetch(context.Background())

		if err == nil {
			t.Fatal("Fetch() error = nil, want error for non-existent file")
		}

		if !strings.Contains(err.Error(), "failed to read file") {
			t.Errorf("Fetch() error = %v, want error containing 'failed to read file'", err)
		}
	})

	t.Run("handles empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "empty.pem")

		if err := os.WriteFile(testFile, []byte{}, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		resolver, err := NewFileResolver(testFile)
		if err != nil {
			t.Fatalf("NewFileResolver() error = %v, want nil", err)
		}

		data, err := resolver.Fetch(context.Background())

		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil", err)
		}

		if len(data) != 0 {
			t.Errorf("Fetch() length = %d, want 0", len(data))
		}
	})

	t.Run("context cancellation does not affect file read", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.pem")
		expectedData := "certificate content"

		if err := os.WriteFile(testFile, []byte(expectedData), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		resolver, err := NewFileResolver(testFile)
		if err != nil {
			t.Fatalf("NewFileResolver() error = %v, want nil", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		data, err := resolver.Fetch(ctx)

		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil (file operations ignore context)", err)
		}

		if string(data) != expectedData {
			t.Errorf("Fetch() = %q, want %q", data, expectedData)
		}
	})
}

func TestNewResolver(t *testing.T) {
	t.Run("creates HTTPS resolver", func(t *testing.T) {
		uri := "https://example.com/cert.cer"

		resolver, err := NewResolver(uri)

		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		_, ok := resolver.(*HTTPSResolver)
		if !ok {
			t.Errorf("NewResolver() type = %T, want *HTTPSResolver", resolver)
		}
	})

	t.Run("creates HTTPS resolver with custom HTTP client", func(t *testing.T) {
		uri := "https://example.com/cert.cer"
		customClient := &http.Client{}

		resolver, err := NewResolver(uri, customClient)

		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		httpsResolver, ok := resolver.(*HTTPSResolver)
		if !ok {
			t.Fatalf("NewResolver() type = %T, want *HTTPSResolver", resolver)
		}

		if httpsResolver.httpClient != customClient {
			t.Error("NewResolver() httpClient mismatch")
		}
	})

	t.Run("creates file resolver with absolute path", func(t *testing.T) {
		uri := "file:///home/user/cert.pem"

		resolver, err := NewResolver(uri)

		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		_, ok := resolver.(*FileResolver)
		if !ok {
			t.Errorf("NewResolver() type = %T, want *FileResolver", resolver)
		}
	})

	t.Run("rejects http scheme", func(t *testing.T) {
		uri := "http://example.com/cert.cer"

		_, err := NewResolver(uri)

		if err == nil {
			t.Fatal("NewResolver() error = nil, want error for http scheme")
		}

		if !strings.Contains(err.Error(), "unsupported URI scheme 'http'") {
			t.Errorf("NewResolver() error = %v, want error containing 'unsupported URI scheme'", err)
		}
	})

	t.Run("rejects ftp scheme", func(t *testing.T) {
		uri := "ftp://example.com/cert.cer"

		_, err := NewResolver(uri)

		if err == nil {
			t.Fatal("NewResolver() error = nil, want error for ftp scheme")
		}

		if !strings.Contains(err.Error(), "unsupported URI scheme 'ftp'") {
			t.Errorf("NewResolver() error = %v, want error containing 'unsupported URI scheme'", err)
		}
	})

	t.Run("rejects empty scheme", func(t *testing.T) {
		uri := "example.com/cert.cer"

		_, err := NewResolver(uri)

		if err == nil {
			t.Fatal("NewResolver() error = nil, want error for missing scheme")
		}

		if !strings.Contains(err.Error(), "unsupported URI scheme") {
			t.Errorf("NewResolver() error = %v, want error containing 'unsupported URI scheme'", err)
		}
	})

	t.Run("handles invalid URI", func(t *testing.T) {
		uri := "://invalid"

		_, err := NewResolver(uri)

		if err == nil {
			t.Fatal("NewResolver() error = nil, want error for invalid URI")
		}

		if !strings.Contains(err.Error(), "invalid URI") {
			t.Errorf("NewResolver() error = %v, want error containing 'invalid URI'", err)
		}
	})

	t.Run("rejects file resolver with relative path", func(t *testing.T) {
		uri := "file://certs/cert.pem"

		_, err := NewResolver(uri)

		if err == nil {
			t.Fatal("NewResolver() error = nil, want error for relative path")
		}

		if !strings.Contains(err.Error(), "relative paths are not supported") {
			t.Errorf("NewResolver() error = %v, want error containing 'relative paths are not supported'", err)
		}
	})

	t.Run("uses default HTTP client when none provided", func(t *testing.T) {
		uri := "https://example.com/cert.cer"

		resolver, err := NewResolver(uri)

		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		httpsResolver, ok := resolver.(*HTTPSResolver)
		if !ok {
			t.Fatalf("NewResolver() type = %T, want *HTTPSResolver", resolver)
		}

		if httpsResolver.httpClient != defaultClient {
			t.Error("NewResolver() should use defaultClient when none provided")
		}
	})

	t.Run("ignores additional HTTP client parameters", func(t *testing.T) {
		uri := "https://example.com/cert.cer"
		client1 := &http.Client{}
		client2 := &http.Client{}

		resolver, err := NewResolver(uri, client1, client2)

		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		httpsResolver, ok := resolver.(*HTTPSResolver)
		if !ok {
			t.Fatalf("NewResolver() type = %T, want *HTTPSResolver", resolver)
		}

		if httpsResolver.httpClient != client1 {
			t.Error("NewResolver() should use first HTTP client only")
		}
	})
}

func TestResolver_Integration(t *testing.T) {
	t.Run("HTTPS resolver end-to-end", func(t *testing.T) {
		expectedData := "PEM certificate data"
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(expectedData))
		}))
		defer server.Close()

		resolver, err := NewResolver(server.URL, server.Client())
		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		data, err := resolver.Fetch(context.Background())
		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil", err)
		}

		if string(data) != expectedData {
			t.Errorf("Fetch() = %q, want %q", data, expectedData)
		}
	})

	t.Run("file resolver end-to-end", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "root.pem")
		expectedData := "PEM certificate data"

		if err := os.WriteFile(testFile, []byte(expectedData), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		uri := "file://" + testFile
		resolver, err := NewResolver(uri)
		if err != nil {
			t.Fatalf("NewResolver() error = %v, want nil", err)
		}

		data, err := resolver.Fetch(context.Background())
		if err != nil {
			t.Fatalf("Fetch() error = %v, want nil", err)
		}

		if string(data) != expectedData {
			t.Errorf("Fetch() = %q, want %q", data, expectedData)
		}
	})
}
