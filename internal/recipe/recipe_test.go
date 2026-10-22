package recipe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A missed required anchor must leave the file byte-identical.
//
// This is the single most important property: a half-applied Python file is
// worse than no patch at all, because the customer's install stops importing
// and they blame the tool.
func TestRequiredMissWritesNothing(t *testing.T) {
	orig := "alpha\nbeta\ngamma\n"
	p := writeTemp(t, "target.py", orig)

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-miss",
		Target: Target{Kind: "python_file", Path: p},
		Ops: []Op{
			{Op: "replace", Find: "alpha", With: "ALPHA", Count: 1, Required: true},
			{Op: "replace", Find: "NOT-THERE", With: "x", Count: 1, Required: true},
		},
	}}}

	res := Apply(b, Options{Platform: "linux"})
	if len(res) != 1 || res[0].Status != "missing_anchor" {
		t.Fatalf("want missing_anchor, got %+v", res)
	}
	if got := readFile(t, p); got != orig {
		t.Fatalf("file was modified despite a missed required anchor:\n%q", got)
	}
}

// An optional miss is tolerated and the rest of the recipe still applies.
func TestOptionalMissStillApplies(t *testing.T) {
	p := writeTemp(t, "target.py", "alpha\nbeta\n")

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-opt",
		Target: Target{Kind: "python_file", Path: p},
		Ops: []Op{
			{Op: "replace", Find: "alpha", With: "ALPHA", Count: 1, Required: true},
			{Op: "replace", Find: "NOT-THERE", With: "x", Count: 1, Required: false},
		},
	}}}

	res := Apply(b, Options{Platform: "linux"})
	if res[0].Status != "applied" {
		t.Fatalf("want applied, got %+v", res)
	}
	if got := readFile(t, p); !strings.HasPrefix(got, "ALPHA") {
		t.Fatalf("required op not applied: %q", got)
	}
}

// Second run must be a no-op. This is what makes the hourly timer safe.
func TestIdempotent(t *testing.T) {
	p := writeTemp(t, "target.py", "alpha\n")

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-idem",
		Target: Target{Kind: "python_file", Path: p},
		Detect: &Detect{ContainsAny: []string{"ALPHA"}},
		Ops:    []Op{{Op: "replace", Find: "alpha", With: "ALPHA", Count: 1, Required: true}},
	}}}

	if res := Apply(b, Options{Platform: "linux"}); res[0].Status != "applied" {
		t.Fatalf("first run: want applied, got %+v", res)
	}
	if res := Apply(b, Options{Platform: "linux"}); res[0].Status != "already" {
		t.Fatalf("second run: want already, got %+v", res)
	}
	if got := readFile(t, p); got != "ALPHA\n" {
		t.Fatalf("content drifted: %q", got)
	}
}

// DryRun reports the transformation without touching disk.
func TestDryRun(t *testing.T) {
	orig := "alpha\n"
	p := writeTemp(t, "target.py", orig)

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-dry",
		Target: Target{Kind: "python_file", Path: p},
		Ops:    []Op{{Op: "replace", Find: "alpha", With: "ALPHA", Count: 1, Required: true}},
	}}}

	res := Apply(b, Options{Platform: "linux", DryRun: true})
	if res[0].Status != "dry_run" {
		t.Fatalf("want dry_run, got %+v", res)
	}
	if got := readFile(t, p); got != orig {
		t.Fatalf("dry run wrote to disk: %q", got)
	}
}

// count limits the number of replacements, which matters for literals that
// legitimately appear more than once in a minified bundle.
func TestReplaceCount(t *testing.T) {
	p := writeTemp(t, "bundle.js", "x=1;x=1;x=1;")

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-count",
		Target: Target{Kind: "text_file", Path: p},
		Ops:    []Op{{Op: "replace", Find: "x=1", With: "x=2", Count: 2, Required: true}},
	}}}

	Apply(b, Options{Platform: "linux"})
	if got := readFile(t, p); got != "x=2;x=2;x=1;" {
		t.Fatalf("want 2 replacements, got %q", got)
	}
}

// regex_replace with a count cap.
func TestRegexReplaceCount(t *testing.T) {
	p := writeTemp(t, "f.txt", "a1 a2 a3")

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-regex",
		Target: Target{Kind: "text_file", Path: p},
		Ops:    []Op{{Op: "regex_replace", Pattern: `a(\d)`, With: "b$1", Count: 2, Required: true}},
	}}}

	res := Apply(b, Options{Platform: "linux"})
	if res[0].Status != "applied" {
		t.Fatalf("want applied, got %+v", res)
	}
	if got := readFile(t, p); got != "b1 b2 a3" {
		t.Fatalf("want b1 b2 a3, got %q", got)
	}
}

// insert_after leaves the anchor in place and appends.
func TestInsertAfter(t *testing.T) {
	p := writeTemp(t, "f.py", "def f():\n    pass\n")

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-ins",
		Target: Target{Kind: "python_file", Path: p},
		Ops:    []Op{{Op: "insert_after", Find: "def f():", With: "\n    return None", Required: true}},
	}}}

	Apply(b, Options{Platform: "linux"})
	want := "def f():\n    return None\n    pass\n"
	if got := readFile(t, p); got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

// A recipe tagged for another platform is skipped, not failed.
func TestPlatformSkip(t *testing.T) {
	p := writeTemp(t, "f.py", "alpha\n")

	b := &Bundle{Version: 1, Recipes: []Recipe{{
		ID:     "t-plat",
		Target: Target{Kind: "python_file", Path: p, Platforms: []string{"windows"}},
		Ops:    []Op{{Op: "replace", Find: "alpha", With: "ALPHA", Count: 1, Required: true}},
	}}}

	res := Apply(b, Options{Platform: "linux"})
	if res[0].Status != "skipped" {
		t.Fatalf("want skipped, got %+v", res)
	}
}

// Every payload shipped in payloads/ must parse and carry unique ids.
func TestShippedPayloadsParse(t *testing.T) {
	dir := "../../payloads"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("payloads dir not present")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if b.Version < 1 {
			t.Fatalf("%s: version must be >= 1", e.Name())
		}
		for _, r := range b.Recipes {
			if r.ID == "" || r.Target.Path == "" || len(r.Ops) == 0 {
				t.Fatalf("%s: incomplete recipe %+v", e.Name(), r)
			}
			if seen[r.ID] {
				t.Fatalf("%s: duplicate recipe id %q", e.Name(), r.ID)
			}
			seen[r.ID] = true
			for _, op := range r.Ops {
				switch op.Op {
				case "replace", "insert_after", "append":
					if op.Find == "" {
						t.Fatalf("%s/%s: op %q needs find", e.Name(), r.ID, op.Op)
					}
				case "regex_replace":
					if op.Pattern == "" {
						t.Fatalf("%s/%s: regex_replace needs pattern", e.Name(), r.ID)
					}
				default:
					t.Fatalf("%s/%s: unknown op %q", e.Name(), r.ID, op.Op)
				}
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no recipes found in payloads/")
	}
	t.Logf("validated %d recipes", len(seen))
}
