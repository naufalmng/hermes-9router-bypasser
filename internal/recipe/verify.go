package recipe

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Check is the outcome of verifying one target after the writes are done.
//
// The customer's question is not "did the tool exit 0" — it is "is this machine
// actually patched now, and is it still usable". Two independent proofs:
//
//	marker — the replacement text is present in the file (the patch landed)
//	syntax — the file still parses with its own interpreter (we did not break it)
//
// Both must pass. A marker without syntax means we corrupted the file; syntax
// without a marker means the patch silently did nothing.
type Check struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Marker bool   `json:"marker"`
	Syntax bool   `json:"syntax"`
	SyntaxKind string `json:"syntax_kind"` // python | node | skipped
	Detail string `json:"detail,omitempty"`
	OK     bool   `json:"ok"`
}

// VerifyAll re-reads every file the run claims to have handled.
//
// Only recipes that reported applied or already are checked: skipped targets
// (the app is not installed) and failures have nothing to prove.
func VerifyAll(b *Bundle, results []Result, o Options) []Check {
	byID := make(map[string]Result, len(results))
	for _, r := range results {
		byID[r.ID] = r
	}
	out := make([]Check, 0, len(b.Recipes))
	for _, rec := range b.Recipes {
		res, ok := byID[rec.ID]
		if !ok {
			continue
		}
		switch res.Status {
		case "applied", "already", "verify_failed":
		default:
			continue
		}
		path, err := ExpandPath(rec.Target.Path, o.Home)
		if err != nil {
			out = append(out, Check{ID: rec.ID, Path: rec.Target.Path, Detail: err.Error()})
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			out = append(out, Check{ID: rec.ID, Path: path, Detail: "unreadable: " + err.Error()})
			continue
		}
		c := Check{ID: rec.ID, Path: path}

		// marker: the patch is present
		switch {
		case len(rec.Detect.ContainsAny) > 0:
			c.Marker = false
			for _, m := range rec.Detect.ContainsAny {
				if m != "" && bytes.Contains(raw, []byte(m)) {
					c.Marker = true
					break
				}
			}
		case rec.Detect.Contains != "":
			c.Marker = bytes.Contains(raw, []byte(rec.Detect.Contains))
		default:
			// No detect rule: fall back to the replacement text of the first
			// required op, which is what should now be in the file.
			for _, op := range rec.Ops {
				if op.Required && op.With != "" {
					c.Marker = bytes.Contains(raw, []byte(op.With))
					break
				}
			}
		}

		// syntax: the file still parses
		c.SyntaxKind, c.Syntax, c.Detail = checkSyntax(path, o)
		c.OK = c.Marker && c.Syntax
		out = append(out, c)
	}
	return out
}

// checkSyntax runs the file's own parser over it. Nothing is written: the Python
// check uses compile() on the bytes rather than py_compile, so a customer's tree
// gains no __pycache__ entries from a verification pass.
func checkSyntax(path string, o Options) (kind string, ok bool, detail string) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		py := findPython(o.Home)
		if py == "" {
			return "skipped", true, "no python interpreter found"
		}
		cmd := exec.Command(py, "-c",
			"import sys;compile(open(sys.argv[1],'rb').read(), sys.argv[1], 'exec')", path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return "python", false, msg
		}
		return "python", true, ""
	case ".js", ".mjs", ".cjs":
		node, err := exec.LookPath("node")
		if err != nil {
			return "skipped", true, "node not on PATH"
		}
		cmd := exec.Command(node, "--check", path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return "node", false, msg
		}
		return "node", true, ""
	}
	return "skipped", true, ""
}

// findPython prefers the interpreter that actually runs Hermes — the venv next
// to the install — because that is the one whose version must accept the file.
// A system python3 can be a different major version and give a false pass.
func findPython(hermesRoot string) string {
	// Interpreter file names differ per OS: a Linux venv has no `.exe`.
	names := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		names = []string{"python.exe", "python3.exe"}
	}
	dirs := []string{"Scripts", "bin"}
	for _, sub := range []string{"venv", ".venv"} {
		for _, d := range dirs {
			for _, n := range names {
				p := filepath.Join(hermesRoot, sub, d, n)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p
				}
			}
		}
	}
	cands := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		cands = []string{"python", "py"}
	}
	for _, c := range cands {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// Summary is the one-line verdict printed at the end.
func Summary(checks []Check) (done bool, line string) {
	total, bad := len(checks), 0
	var failed []string
	for _, c := range checks {
		if !c.OK {
			bad++
			failed = append(failed, c.ID)
		}
	}
	if total == 0 {
		return false, "BELUM SELESAI — tidak ada target yang bisa diverifikasi"
	}
	if bad == 0 {
		return true, fmt.Sprintf("SELESAI — %d/%d terverifikasi", total, total)
	}
	return false, fmt.Sprintf("BELUM SELESAI — %d/%d gagal: %s", bad, total, strings.Join(failed, ", "))
}
