package main

import (
	"context"
	"os"
	"strconv"
	"sync"
)

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if n <= 0 {
		return def
	}
	return n
}

// runBatched runs fn over batches with a max concurrency limit.
func runBatched[T any, R any](ctx context.Context, batches [][]T, concurrency int, fn func(context.Context, []T) (R, error)) ([]R, []error) {
	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	results := make([]R, len(batches))
	errs := make([]error, len(batches))

	var wg sync.WaitGroup
	for i := range batches {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			defer func() { <-sem }()

			r, err := fn(ctx, batches[i])
			if err != nil {
				errs[i] = err
				return
			}
			results[i] = r
		}()
	}
	wg.Wait()
	return results, errs
}

func chunkSlice[T any](in []T, size int) [][]T {
	if size <= 0 || len(in) == 0 {
		return nil
	}
	var out [][]T
	for i := 0; i < len(in); i += size {
		j := i + size
		if j > len(in) {
			j = len(in)
		}
		out = append(out, in[i:j])
	}
	return out
}
