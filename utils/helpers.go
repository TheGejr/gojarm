package utils

import "time"

var DefualtBackoff = func(r, m int) (backoff time.Duration) {
	return time.Second
}
