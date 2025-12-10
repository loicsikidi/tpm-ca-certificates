package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFile(t *testing.T) {
	t.Run("reads small file with default max size", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("hello world")

		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		data, err := ReadFile(testFile)
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

		data, err := ReadFile(testFile, 10)
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

		largeContent := strings.Repeat("a", int(DefaultMaxFileSize)+1)
		if err := os.WriteFile(testFile, []byte(largeContent), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		_, err := ReadFile(testFile)
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

		_, err := ReadFile(testFile, 100)
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

		data, err := ReadFile(testFile, maxSize)
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

		data, err := ReadFile(testFile)
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

		data, err := ReadFile(testFile, 10, 20, 30)
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}

		if string(data) != string(content) {
			t.Errorf("ReadFile() = %q, want %q", data, content)
		}
	})
}
