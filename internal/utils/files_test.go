package utils_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

func TestReadFile(t *testing.T) {
	t.Run("reads small file with default max size", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("hello world")

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := utils.ReadFile(testFile)
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}

		if string(data) != string(content) {
			t.Errorf("ReadFile() = %q, want %q", data, content)
		}
	})

	t.Run("reads file with custom max size", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("hello")

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := utils.ReadFile(testFile, 10)
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}

		if string(data) != string(content) {
			t.Errorf("ReadFile() = %q, want %q", data, content)
		}
	})

	t.Run("rejects file exceeding default max size", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "large.txt")

		largeContent := strings.Repeat("a", int(utils.DefaultMaxFileSize)+1)
		if err := os.WriteFile(testFile, []byte(largeContent), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		_, err := utils.ReadFile(testFile)
		if err == nil {
			t.Fatal("ReadFile() error = nil, want error for file too large")
		}

		if !strings.Contains(err.Error(), "file too large") {
			t.Errorf("ReadFile() error = %v, want error containing 'file too large'", err)
		}
	})

	t.Run("rejects file exceeding custom max size", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := strings.Repeat("a", 101)

		if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		_, err := utils.ReadFile(testFile, 100)
		if err == nil {
			t.Fatal("ReadFile() error = nil, want error for file too large")
		}

		if !strings.Contains(err.Error(), "file too large") {
			t.Errorf("ReadFile() error = %v, want error containing 'file too large'", err)
		}
		if !strings.Contains(err.Error(), "100 bytes") {
			t.Errorf("ReadFile() error = %v, want error mentioning max size of 100 bytes", err)
		}
	})

	t.Run("reads file at exact max size", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "exact.txt")
		maxSize := int64(100)
		content := strings.Repeat("a", int(maxSize))

		if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := utils.ReadFile(testFile, maxSize)
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}

		if int64(len(data)) != maxSize {
			t.Errorf("ReadFile() length = %d, want %d", len(data), maxSize)
		}
	})

	t.Run("handles binary content", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "binary.bin")
		content := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := utils.ReadFile(testFile)
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}

		if len(data) != len(content) {
			t.Fatalf("ReadFile() length = %d, want %d", len(data), len(content))
		}

		for i, b := range content {
			if data[i] != b {
				t.Errorf("ReadFile() data[%d] = 0x%02X, want 0x%02X", i, data[i], b)
			}
		}
	})

	t.Run("ignores additional maxSize parameters beyond first", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("test")

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := utils.ReadFile(testFile, 10, 20, 30)
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}

		if string(data) != string(content) {
			t.Errorf("ReadFile() = %q, want %q", data, content)
		}
	})

	t.Run("reads from stdin with dash", func(t *testing.T) {
		content := []byte("hello from stdin")
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdin = r

		go func() {
			defer w.Close()
			w.Write(content)
		}()

		data, err := utils.ReadFile("-")
		if err != nil {
			t.Fatalf("ReadFile(\"-\") error = %v, want nil", err)
		}

		if !bytes.Equal(data, content) {
			t.Errorf("ReadFile(\"-\") = %q, want %q", data, content)
		}
	})

	t.Run("reads from stdin with custom max size", func(t *testing.T) {
		content := []byte("test")
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdin = r

		go func() {
			defer w.Close()
			w.Write(content)
		}()

		data, err := utils.ReadFile("-", 10)
		if err != nil {
			t.Fatalf("ReadFile(\"-\", 10) error = %v, want nil", err)
		}

		if !bytes.Equal(data, content) {
			t.Errorf("ReadFile(\"-\", 10) = %q, want %q", data, content)
		}
	})

	t.Run("rejects stdin exceeding max size", func(t *testing.T) {
		content := []byte(strings.Repeat("a", 101))
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdin = r

		go func() {
			defer w.Close()
			w.Write(content)
		}()

		_, err = utils.ReadFile("-", 100)
		if err == nil {
			t.Fatal("ReadFile(\"-\", 100) error = nil, want error for stdin too large")
		}

		if !strings.Contains(err.Error(), "file too large") {
			t.Errorf("ReadFile(\"-\", 100) error = %v, want error containing 'file too large'", err)
		}
		if !strings.Contains(err.Error(), "100 bytes") {
			t.Errorf("ReadFile(\"-\", 100) error = %v, want error mentioning max size of 100 bytes", err)
		}
	})

	t.Run("reads binary content from stdin", func(t *testing.T) {
		content := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdin = r

		go func() {
			defer w.Close()
			w.Write(content)
		}()

		data, err := utils.ReadFile("-")
		if err != nil {
			t.Fatalf("ReadFile(\"-\") error = %v, want nil", err)
		}

		if !bytes.Equal(data, content) {
			t.Errorf("ReadFile(\"-\") = %v, want %v", data, content)
		}
	})

	t.Run("reads empty stdin", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdin = r

		go func() {
			w.Close()
		}()

		data, err := utils.ReadFile("-")
		if err != nil {
			t.Fatalf("ReadFile(\"-\") error = %v, want nil", err)
		}

		if len(data) != 0 {
			t.Errorf("ReadFile(\"-\") = %q, want empty", data)
		}
	})

	t.Run("handles stdin read error", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stdin = r

		// Close both ends to simulate read error
		r.Close()
		w.Close()

		_, err = utils.ReadFile("-")
		if err == nil {
			t.Fatal("ReadFile(\"-\") error = nil, want error for closed stdin")
		}

		if !strings.Contains(err.Error(), "file already closed") {
			t.Logf("ReadFile(\"-\") error = %v (note: this is expected)", err)
		}
	})
}
