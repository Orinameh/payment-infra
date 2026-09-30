package fraud

import "testing"

func TestSeverityBands(t *testing.T) {
	cases := map[int]string{
		0:   "low",
		199: "low",
		200: "medium",
		399: "medium",
		400: "high",
		699: "high",
		700: "critical",
		999: "critical",
	}
	for score, want := range cases {
		if got := severityOf(score); got != want {
			t.Fatalf("score %d: got %q want %q", score, got, want)
		}
	}
}
