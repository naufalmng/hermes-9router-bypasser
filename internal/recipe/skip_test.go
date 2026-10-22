package recipe

import (
	"os"
	"path/filepath"
	"testing"
)

// A customer without 9router must not see a failed run. Skipped is the correct
// status, and it must not trip the non-zero exit.
func TestMissing9routerSkips(t *testing.T) {
	t.Setenv("H9B_ROUTER9_CHUNKS", "")
	orig := router9Roots
	router9Roots = func(_, _, _ string) []string { return nil }
	t.Cleanup(func() { router9Roots = orig })
	home := t.TempDir()
	b := &Bundle{Version: 1, ID: "t", Recipes: []Recipe{{
		ID: "r9-x",
		Target: Target{
			Path:      "{router9_chunks}/5330.js",
			Platforms: []string{"linux", "windows", "darwin"},
		},
		Ops: []Op{{Op: "replace", Find: "a", With: "b", Required: true}},
	}}}
	res := Apply(b, Options{Home: home, Platform: "linux", DryRun: true})
	if res[0].Status != "skipped" {
		t.Fatalf("status = %q, want skipped (detail %q)", res[0].Status, res[0].Detail)
	}
}

func TestMissingHermesSkips(t *testing.T) {
	t.Setenv("H9B_HERMES_ROOT", "")
	home := t.TempDir()
	b := &Bundle{Version: 1, ID: "t", Recipes: []Recipe{{
		ID:     "hg-x",
		Target: Target{Path: "{hermes_agent}/tools/threat_patterns.py"},
		Ops:    []Op{{Op: "replace", Find: "a", With: "b", Required: true}},
	}}}
	res := Apply(b, Options{Home: home, Platform: "linux", DryRun: true})
	if res[0].Status != "skipped" {
		t.Fatalf("status = %q, want skipped (detail %q)", res[0].Status, res[0].Detail)
	}
}

// The distinction that matters: app present, file gone => real drift, reported.
func TestInstalledAppMissingFileIsNotSkipped(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".hermes", "hermes-agent")
	if err := os.MkdirAll(filepath.Join(root, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tools", "threat_patterns.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("H9B_HERMES_ROOT", "")
	b := &Bundle{Version: 1, ID: "t", Recipes: []Recipe{{
		ID:     "hg-gone",
		Target: Target{Path: "{hermes_agent}/tools/no_such_file.py"},
		Ops:    []Op{{Op: "replace", Find: "a", With: "b", Required: true}},
	}}}
	res := Apply(b, Options{Home: home, Platform: "linux", DryRun: true})
	if res[0].Status == "skipped" {
		t.Fatalf("file drift was swallowed as skipped: %+v", res[0])
	}
}
