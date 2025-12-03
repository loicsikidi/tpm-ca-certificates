package concurrency

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// MaxWorkers defines the maximum number of concurrent workers allowed.
const MaxWorkers = 10

// DetectCPUCount determines the optimal number of workers based on container quota or logical CPUs.
//
// It first checks for Linux container CPU quota by reading /sys/fs/cgroup files.
// If no quota is found or the quota is unlimited, it falls back to runtime.NumCPU().
// The result is capped at [MaxWorkers].
//
// Example:
//
//	workers := concurrency.DetectCPUCount()
//	fmt.Printf("Using %d workers\n", workers)
func DetectCPUCount() int {
	// Try to detect container CPU quota (cgroup v2 first, then v1)
	if quota := detectCgroupCPUQuota(); quota > 0 {
		return min(quota, MaxWorkers)
	}

	// Fall back to number of logical CPUs
	return min(runtime.NumCPU(), MaxWorkers)
}

// detectCgroupCPUQuota attempts to read CPU quota from cgroup files.
func detectCgroupCPUQuota() int {
	// Try cgroup v2 first
	if quota := readCgroupV2Quota(); quota > 0 {
		return quota
	}

	// Try cgroup v1
	if quota := readCgroupV1Quota(); quota > 0 {
		return quota
	}

	return 0
}

// readCgroupV2Quota reads CPU quota from cgroup v2.
func readCgroupV2Quota() int {
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}

	// Format: "quota period"
	// If quota is "max", there's no limit
	if fields[0] == "max" {
		return 0
	}

	quota, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0
	}

	period, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}

	if period == 0 {
		return 0
	}

	// Calculate number of CPUs from quota/period
	cpus := (quota + period - 1) / period // Round up
	if cpus < 1 {
		return 1
	}

	return cpus
}

// readCgroupV1Quota reads CPU quota from cgroup v1.
func readCgroupV1Quota() int {
	quotaData, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	if err != nil {
		return 0
	}

	periodData, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if err != nil {
		return 0
	}

	quota, err := strconv.Atoi(strings.TrimSpace(string(quotaData)))
	if err != nil || quota <= 0 {
		return 0
	}

	period, err := strconv.Atoi(strings.TrimSpace(string(periodData)))
	if err != nil || period <= 0 {
		return 0
	}

	// Calculate number of CPUs from quota/period
	cpus := (quota + period - 1) / period // Round up
	if cpus < 1 {
		return 1
	}

	return cpus
}
