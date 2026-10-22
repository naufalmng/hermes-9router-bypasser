package cdk

import "testing"

func TestGenerateValidates(t *testing.T) {
	for i := 0; i < 200; i++ {
		k := Generate()
		if !Validate(k) {
			t.Fatalf("generated key does not validate: %s", k)
		}
	}
}

func TestNormalizeAcceptsSloppyInput(t *testing.T) {
	k := Generate()
	flat := Normalize(k) // 18 chars, no prefix, no dashes
	if len(flat) != 18 {
		t.Fatalf("normalised body should be 18 chars, got %d (%q)", len(flat), flat)
	}
	cases := map[string]string{
		"lowercase":    lower(flat),
		"spaces":       "  " + flat + "  ",
		"prefixed":     Prefix + "-" + flat,
		"dashed":       flat[0:5] + "-" + flat[5:10] + "-" + flat[10:15] + "-" + flat[15:],
		"lower+dashed": lower(Prefix + "-" + flat[0:5] + "-" + flat[5:10] + "-" + flat[10:15] + "-" + flat[15:]),
	}
	for name, in := range cases {
		if got := Normalize(in); got != flat {
			t.Fatalf("%s: want %q, got %q (input %q)", name, flat, got, in)
		}
		if !Validate(in) {
			t.Fatalf("%s: input did not validate: %q", name, in)
		}
	}
}

func TestTamperedChecksumRejected(t *testing.T) {
	k := Generate()
	flat := Normalize(k)
	// flip the final character to a different alphabet symbol
	last := flat[len(flat)-1]
	repl := byte('0')
	if last == repl {
		repl = '1'
	}
	bad := flat[:len(flat)-1] + string(repl)
	if Validate(bad) {
		t.Fatalf("tampered key validated: %s -> %s", flat, bad)
	}
}

func TestValidateRejectsJunk(t *testing.T) {
	for _, s := range []string{"", "H9B", "hello world", "H9B-AAAA", "000000000000000000"} {
		if Validate(s) {
			t.Fatalf("junk validated: %q", s)
		}
	}
}

func TestMaskHidesBody(t *testing.T) {
	k := Generate()
	m := Mask(k)
	if m == "" || m == k {
		t.Fatalf("mask should differ from key: %q", m)
	}
	// Compare like for like: dashes are cosmetic in both renderings.
	bare := func(s string) string {
		return lower(replaceDash(s))
	}
	if len(bare(m)) >= len(bare(Normalize(k))) {
		t.Fatalf("mask does not hide anything: %q", m)
	}
	// The mask must never contain the middle of the key.
	if containsStr(lower(m), lower(Normalize(k)[4:13])) {
		t.Fatalf("mask leaks the body: %q", m)
	}
}

func replaceDash(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func containsStr(h, n string) bool {
	if len(n) == 0 || len(h) < len(n) {
		return false
	}
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
