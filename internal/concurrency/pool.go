package concurrency

import "sync"

// Execute processes items concurrently using a worker pool.
// It takes the number of workers, a slice of items, and a processor function.
// The processor receives both the index and the item.
// Results maintain the same order as the input items.
//
// If workers is 0, it auto-detects the optimal count using [DetectCPUCount].
// The number of workers is capped at [MaxWorkers].
//
// Example:
//
//	type Input struct { URL string }
//	type Result struct { Data []byte; Err error }
//
//	inputs := []Input{{URL: "http://example.com"}}
//	results := concurrency.Execute(5, inputs, func(idx int, input Input) Result {
//	    data, err := downloadURL(input.URL)
//	    return Result{Data: data, Err: err}
//	})
func Execute[T any, R any](workers int, items []T, processor func(int, T) R) []R {
	if workers == 0 {
		workers = DetectCPUCount()
	}
	if workers > MaxWorkers {
		workers = MaxWorkers
	}
	if workers < 1 {
		workers = 1
	}

	results := make([]R, len(items))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, workers)

	for i, item := range items {
		wg.Add(1)
		go func(idx int, itm T) {
			defer wg.Done()

			// Acquire worker slot
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Process item
			results[idx] = processor(idx, itm)
		}(i, item)
	}

	wg.Wait()
	return results
}
