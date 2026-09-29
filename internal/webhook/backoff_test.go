package webhook

import (
	"testing"
	"time"
)

func TestBackoffSteps(t *testing.T) {
	cases := map[int]time.Duration{
		1:  time.Minute,
		2:  5 * time.Minute,
		3:  15 * time.Minute,
		4:  time.Hour,
		5:  4 * time.Hour,
		6:  12 * time.Hour,
		7:  24 * time.Hour,
		99: 24 * time.Hour,
	}
	for attempt, want := range cases {
		if got := Backoff(attempt); got != want {
			t.Fatalf("attempt %d: got %v want %v", attempt, got, want)
		}
	}
}
