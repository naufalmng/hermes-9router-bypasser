package tier

import "testing"

// The whole commercial model is this matrix. A Basic customer must not receive
// the other product's recipes, because anything the client receives can be
// dumped from its memory.
func TestAllows(t *testing.T) {
	cases := []struct {
		tier   string
		recipe string
		want   bool
	}{
		{Hermes, "hg-threat-patterns", true},
		{Hermes, "hg-cron-scan", true},
		{Hermes, "r9-codebuddy-cn", false},

		{Router9, "r9-codebuddy-cn", true},
		{Router9, "r9-gemini-safety", true},
		{Router9, "hg-threat-patterns", false},

		{Pro, "hg-threat-patterns", true},
		{Pro, "r9-codebuddy-cn", true},

		// core recipes apply to everyone
		{Hermes, "core-something", true},
		{Router9, "core-something", true},
		{Pro, "core-something", true},

		// fail closed: a typo in `cdk new -tier` must not hand out Pro
		{"", "hg-threat-patterns", false},
		{"premium", "r9-codebuddy-cn", false},
		{"PRO", "hg-threat-patterns", false}, // unnormalised tier is not valid
	}
	for _, c := range cases {
		if got := Allows(c.tier, c.recipe); got != c.want {
			t.Errorf("Allows(%q, %q) = %v, want %v", c.tier, c.recipe, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"pro":           Pro,
		"PRO":           Pro,
		"both":          Pro,
		"basic-hermes":  Hermes,
		"hermes":        Hermes,
		"Basic_Hermes":  Hermes,
		"basic-router9": Router9,
		"router9":       Router9,
		"9router":       Router9,
		"basic-9router": Router9,
		"  pro  ":       Pro,
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}

	// Bare "basic" is ambiguous: two products share the name.
	if _, err := Normalize("basic"); err == nil {
		t.Error(`Normalize("basic") should refuse: it names two products`)
	}
	if _, err := Normalize("gold"); err == nil {
		t.Error(`Normalize("gold") should refuse`)
	}
}

func TestLabel(t *testing.T) {
	for _, tr := range []string{Hermes, Router9, Pro} {
		if Label(tr) == tr {
			t.Errorf("Label(%q) returned the raw value; want a human name", tr)
		}
	}
	if Label("weird") != "weird" {
		t.Error("unknown tier should fall through unchanged")
	}
}
