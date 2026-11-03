package tui

import "time"

func trafficRate(current, previous int64, elapsed time.Duration) int64 {
	if elapsed <= 0 || current <= previous {
		return 0
	}
	return int64(float64(current-previous) / elapsed.Seconds())
}
