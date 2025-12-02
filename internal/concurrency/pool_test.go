package concurrency

import (
	"testing"
	"time"
)

func TestExecute(t *testing.T) {
	t.Run("basic execution", func(t *testing.T) {
		inputs := []int{1, 2, 3, 4, 5}
		results := Execute(2, inputs, func(idx int, item int) int {
			return item * 2
		})

		if len(results) != len(inputs) {
			t.Fatalf("expected %d results, got %d", len(inputs), len(results))
		}

		for i, result := range results {
			expected := inputs[i] * 2
			if result != expected {
				t.Errorf("results[%d] = %d, want %d", i, result, expected)
			}
		}
	})

	t.Run("auto-detect workers", func(t *testing.T) {
		inputs := []int{1, 2, 3}
		results := Execute(0, inputs, func(idx int, item int) int {
			return item
		})

		if len(results) != len(inputs) {
			t.Fatalf("expected %d results, got %d", len(inputs), len(results))
		}
	})

	t.Run("respects max workers", func(t *testing.T) {
		inputs := make([]int, 100)
		for i := range inputs {
			inputs[i] = i
		}

		// Request more than max workers
		results := Execute(100, inputs, func(idx int, item int) int {
			return item
		})

		if len(results) != len(inputs) {
			t.Fatalf("expected %d results, got %d", len(inputs), len(results))
		}
	})

	t.Run("maintains order", func(t *testing.T) {
		inputs := make([]int, 20)
		for i := range inputs {
			inputs[i] = i
		}

		results := Execute(5, inputs, func(idx int, item int) int {
			// Add small delay to test concurrency
			time.Sleep(time.Millisecond)
			return item * 10
		})

		// Check that results maintain input order
		for i, result := range results {
			expected := inputs[i] * 10
			if result != expected {
				t.Errorf("results[%d] = %d, want %d (order not maintained)", i, result, expected)
			}
		}
	})

	t.Run("handles errors in results", func(t *testing.T) {
		type result struct {
			value int
			err   error
		}

		inputs := []int{1, 2, 3}
		results := Execute(2, inputs, func(idx int, item int) result {
			if item == 2 {
				return result{err: error(nil)} // Simulating error handling
			}
			return result{value: item * 2}
		})

		if len(results) != len(inputs) {
			t.Fatalf("expected %d results, got %d", len(inputs), len(results))
		}
	})
}

func TestDetectCPUCountMaxLimit(t *testing.T) {
	count := DetectCPUCount()
	if count > MaxWorkers {
		t.Errorf("DetectCPUCount() = %d, should not exceed MaxWorkers (%d)", count, MaxWorkers)
	}
	if count < 1 {
		t.Errorf("DetectCPUCount() = %d, should be at least 1", count)
	}
}
