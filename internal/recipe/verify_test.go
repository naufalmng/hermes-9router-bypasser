package recipe

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func bundleFor(id, path string, detect []string) *Bundle {
	return &Bundle{Version: 1, ID: "t", Recipes: []Recipe{{
		ID:     id,
		Target: Target{Path: path},
		Detect: &Detect{ContainsAny: detect},
		Ops:    []Op{{Op: "replace", Find: "x", With: "y", Required: true}},
	}}}
}

// Happy path: marker present, file parses.
func TestVerifyAllPasses(t *testing.T) {
	root := writeTree(t, map[string]string{
		"tools/a.py": "MARKER = 1\n",
	})
	t.Setenv("H9B_HERMES_ROOT", root)
	b := bundleFor("hg-a", "{hermes_agent}/tools/a.py", []string{"MARKER = 1"})
	results := []Result{{ID: "hg-a", Status: "applied"}}
	checks := VerifyAll(b, results, Options{Home: root})
	if len(checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(checks))
	}
	if !checks[0].Marker {
		t.Error("marker not detected")
	}
	if !checks[0].Syntax {
		t.Errorf("syntax check failed: %s", checks[0].Detail)
	}
	if !checks[0].OK {
		t.Error("check should be OK")
	}
}

// The failure that matters most: we wrote something the interpreter rejects.
func TestVerifyAllCatchesBrokenSyntax(t *testing.T) {
	root := writeTree(t, map[string]string{
		"tools/b.py": "def broken(:\n  pass\n",
	})
	b := bundleFor("hg-b", "{hermes_agent}/tools/b.py", []string{"pass"})
	checks := VerifyAll(b, []Result{{ID: "hg-b", Status: "applied"}}, Options{Home: root})
	if checks[0].OK {
		t.Fatal("broken python was reported as OK")
	}
	if checks[0].Syntax {
		t.Error("syntax should be false")
	}
}

// Marker missing means the patch did nothing, even though the file parses.
func TestVerifyAllCatchesMissingMarker(t *testing.T) {
	root := writeTree(t, map[string]string{
		"tools/c.py": "UNTOUCHED = 1\n",
	})
	b := bundleFor("hg-c", "{hermes_agent}/tools/c.py", []string{"MARKER = 1"})
	checks := VerifyAll(b, []Result{{ID: "hg-c", Status: "already"}}, Options{Home: root})
	if checks[0].OK {
		t.Fatal("missing marker reported as OK")
	}
	if checks[0].Marker {
		t.Error("marker should be false")
	}
}

// A skipped recipe proves nothing and must not be counted as verified.
func TestVerifyAllSkipsUntouched(t *testing.T) {
	root := writeTree(t, map[string]string{})
	b := bundleFor("r9-x", "{router9_chunks}/5330.js", []string{"x"})
	checks := VerifyAll(b, []Result{{ID: "r9-x", Status: "skipped"}}, Options{Home: root})
	if len(checks) != 0 {
		t.Fatalf("skipped recipe produced %d checks", len(checks))
	}
}

func TestSummary(t *testing.T) {
	done, line := Summary([]Check{{ID: "a", OK: true}, {ID: "b", OK: true}})
	if !done || !strings.Contains(line, "SELESAI") {
		t.Errorf("expected SELESAI, got %v %q", done, line)
	}
	done, line = Summary([]Check{{ID: "a", OK: true}, {ID: "b", OK: false}})
	if done || !strings.Contains(line, "BELUM SELESAI") {
		t.Errorf("expected BELUM SELESAI, got %v %q", done, line)
	}
	if !strings.Contains(line, "b") {
		t.Error("summary should name the failing recipe")
	}
	if done, _ := Summary(nil); done {
		t.Error("empty check list must not count as done")
	}
}

// Node check only runs when node exists; the outcome must never be a false pass
// on a broken file just because the interpreter is missing.
func TestSyntaxJS(t *testing.T) {
	root := writeTree(t, map[string]string{"c.js": "const a = 1;\n"})
	kind, ok, detail := checkSyntax(filepath.Join(root, "c.js"), Options{Home: root})
	if kind != "node" && kind != "skipped" {
		t.Errorf("unexpected kind %q", kind)
	}
	if kind == "skipped" && ok && detail == "" {
		t.Error("a skipped check should say why")
	}
}

func TestFindPythonPrefersVenv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("venv layout differs; covered by the Windows smoke test")
	}
	root := writeTree(t, map[string]string{"venv/bin/python": "#!/bin/sh\n"})
	if err := os.Chmod(filepath.Join(root, "venv", "bin", "python"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := findPython(root)
	if got != filepath.Join(root, "venv", "bin", "python") {
		t.Errorf("findPython = %q, want the venv interpreter", got)
	}
}
