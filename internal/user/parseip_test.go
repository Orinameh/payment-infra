package user

import "testing"

func TestParseIP(t *testing.T) {
	if parseIP("") != nil {
		t.Fatal("empty IP must yield nil (never block the audit write)")
	}
	if parseIP("not-an-ip") != nil {
		t.Fatal("malformed IP must yield nil")
	}
	if ip := parseIP("203.0.113.42"); ip == nil || ip.String() != "203.0.113.42" {
		t.Fatalf("valid IP must parse, got %v", ip)
	}
}
