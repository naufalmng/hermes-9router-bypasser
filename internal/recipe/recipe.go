// Package recipe defines the payload format and the generic patch engine.
//
// This is the whole point of the architecture: the client binary contains no
// patch knowledge at all. It contains a small interpreter. Every anchor string,
// every replacement, every target path arrives encrypted from the server at run
// time. Reversing the binary therefore yields an interpreter, not the product.
//
// A recipe is declarative and idempotent:
//
//	detect  — if the file already contains this marker, skip (safe to re-run)
//	ops     — ordered edits; all required ops must match or nothing is written
//	verify  — optional post-condition command
package recipe

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Target selects the file a recipe edits.
type Target struct {
	Kind      string   `json:"kind"` // python_file | text_file | command
	Path      string   `json:"path"` // supports ~, {home}, {localappdata}, {hermes}, {hermes_agent}
	Root      bool     `json:"root,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
}

// Op is one edit. Exactly one of Find/Pattern is used.
type Op struct {
	Op       string `json:"op"`                // replace | regex_replace | insert_after | append
	Find     string `json:"find,omitempty"`    // literal anchor
	Pattern  string `json:"pattern,omitempty"` // RE2 pattern (regex_replace)
	With     string `json:"with,omitempty"`    // replacement ($1 expansion allowed)
	Count    int    `json:"count,omitempty"`   // 0 = all occurrences
	Required bool   `json:"required"`          // a miss aborts the whole recipe
	Label    string `json:"label,omitempty"`   // human name shown in reports
}

// Detect makes the recipe idempotent.
//
// ContainsAny exists because the same logical bypass may have been installed by
// an older tool with a different marker. Without it, re-running after a partial
// migration would double-patch the file.
type Detect struct {
	Contains    string   `json:"contains,omitempty"`
	ContainsAny []string `json:"contains_any,omitempty"`
	Absent      string   `json:"absent,omitempty"`
}

// Verify is an optional post-condition.
type Verify struct {
	Command string `json:"command"`
	Expect  string `json:"expect,omitempty"`
	Absent  string `json:"absent,omitempty"`
}

// Recipe is one atomic patch unit.
type Recipe struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Target  Target  `json:"target"`
	Detect  *Detect `json:"detect,omitempty"`
	Ops     []Op    `json:"ops"`
	Verify  *Verify `json:"verify,omitempty"`
	Notes   string  `json:"notes,omitempty"`
}

// Bundle is what the server seals and the client decrypts.
type Bundle struct {
	Version int      `json:"version"`
	ID      string   `json:"id"`
	Recipes []Recipe `json:"recipes"`
}

// Result is one recipe's outcome.
type Result struct {
	ID     string   `json:"id"`
	Status string   `json:"status"` // applied | already | dry_run | missing_anchor | no_target | denied | verify_failed | skipped | error
	Detail string   `json:"detail,omitempty"`
	Missed []string `json:"missed,omitempty"`
}

// Options controls a run.
type Options struct {
	Home     string
	Platform string
	DryRun   bool
	Only     []string
	Log      func(string, ...any)
}

func (o *Options) log(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	}
}

// Parse decodes and sanity-checks a bundle.
func Parse(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("recipe: bad bundle: %w", err)
	}
	if len(b.Recipes) == 0 {
		return nil, fmt.Errorf("recipe: empty bundle")
	}
	for i, r := range b.Recipes {
		if r.ID == "" || r.Target.Path == "" {
			return nil, fmt.Errorf("recipe: entry %d missing id/path", i)
		}
	}
	return &b, nil
}

// Apply runs every recipe in the bundle.
func Apply(b *Bundle, o Options) []Result {
	if o.Platform == "" {
		o.Platform = runtime.GOOS
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	out := make([]Result, 0, len(b.Recipes))
	for _, r := range b.Recipes {
		if len(o.Only) > 0 && !contains(o.Only, r.ID) {
			continue
		}
		out = append(out, applyOne(r, o))
	}
	return out
}

func applyOne(r Recipe, o Options) Result {
	if len(r.Target.Platforms) > 0 && !contains(r.Target.Platforms, o.Platform) {
		return Result{ID: r.ID, Status: "skipped", Detail: "platform " + o.Platform}
	}
	path, err := ExpandPath(r.Target.Path, o.Home)
	if err != nil {
		return Result{ID: r.ID, Status: "error", Detail: err.Error()}
	}
	if _, err := os.Stat(path); err != nil {
		return Result{ID: r.ID, Status: "no_target", Detail: path}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			return Result{ID: r.ID, Status: "denied", Detail: path + " (needs elevation)"}
		}
		return Result{ID: r.ID, Status: "error", Detail: err.Error()}
	}
	src := string(data)
	if r.Detect != nil {
		if r.Detect.Contains != "" && strings.Contains(src, r.Detect.Contains) {
			return Result{ID: r.ID, Status: "already", Detail: "marker present"}
		}
		for _, m := range r.Detect.ContainsAny {
			if m != "" && strings.Contains(src, m) {
				return Result{ID: r.ID, Status: "already", Detail: "marker present"}
			}
		}
		if r.Detect.Absent != "" && !strings.Contains(src, r.Detect.Absent) {
			return Result{ID: r.ID, Status: "already", Detail: "target pattern absent"}
		}
	}

	cur := src
	var missed []string
	for _, op := range r.Ops {
		next, ok, err := applyOp(cur, op)
		if err != nil {
			return Result{ID: r.ID, Status: "error", Detail: err.Error()}
		}
		if !ok {
			if op.Required {
				missed = append(missed, opLabel(op))
				continue
			}
			o.log("  ~ %s: optional op missed (%s)", r.ID, opLabel(op))
			continue
		}
		cur = next
	}
	// All-or-nothing: a partial patch is worse than no patch, because the next
	// run's Detect would see the marker and wrongly report "already applied".
	if len(missed) > 0 {
		return Result{ID: r.ID, Status: "missing_anchor", Detail: "upstream changed; recipe needs update", Missed: missed}
	}
	if cur == src {
		return Result{ID: r.ID, Status: "already", Detail: "no change"}
	}
	if o.DryRun {
		return Result{ID: r.ID, Status: "dry_run", Detail: fmt.Sprintf("%d bytes -> %d bytes", len(src), len(cur))}
	}

	if err := backup(path, src); err != nil {
		return Result{ID: r.ID, Status: "error", Detail: "backup failed: " + err.Error()}
	}
	if err := os.WriteFile(path, []byte(cur), 0o644); err != nil {
		if os.IsPermission(err) {
			return Result{ID: r.ID, Status: "denied", Detail: path + " (needs elevation)"}
		}
		return Result{ID: r.ID, Status: "error", Detail: err.Error()}
	}
	if r.Verify != nil && r.Verify.Command != "" {
		if msg, ok := runVerify(*r.Verify); !ok {
			return Result{ID: r.ID, Status: "verify_failed", Detail: msg}
		}
	}
	return Result{ID: r.ID, Status: "applied", Detail: path}
}

func applyOp(s string, op Op) (string, bool, error) {
	switch op.Op {
	case "replace":
		if op.Find == "" {
			return s, false, fmt.Errorf("replace op without find")
		}
		if !strings.Contains(s, op.Find) {
			return s, false, nil
		}
		n := op.Count
		if n <= 0 {
			n = -1
		}
		return strings.Replace(s, op.Find, op.With, n), true, nil
	case "regex_replace":
		re, err := regexp.Compile(op.Pattern)
		if err != nil {
			return s, false, fmt.Errorf("bad pattern %q: %w", op.Pattern, err)
		}
		if !re.MatchString(s) {
			return s, false, nil
		}
		if op.Count <= 0 {
			return re.ReplaceAllString(s, op.With), true, nil
		}
		// Count-limited: expand only the first N matches, leave the rest byte-identical.
		done := 0
		res := re.ReplaceAllStringFunc(s, func(m string) string {
			if done >= op.Count {
				return m
			}
			done++
			return re.ReplaceAllString(m, op.With)
		})
		return res, true, nil
	case "insert_after":
		idx := strings.Index(s, op.Find)
		if idx < 0 {
			return s, false, nil
		}
		cut := idx + len(op.Find)
		return s[:cut] + op.With + s[cut:], true, nil
	case "append":
		return s + op.With, true, nil
	default:
		return s, false, fmt.Errorf("unknown op %q", op.Op)
	}
}

func runVerify(v Verify) (string, bool) {
	out, err := exec.Command("sh", "-c", v.Command).CombinedOutput()
	text := string(out)
	if err != nil {
		return fmt.Sprintf("command failed: %v: %s", err, firstLine(text)), false
	}
	if v.Expect != "" && !strings.Contains(text, v.Expect) {
		return "expected " + v.Expect + " not found", false
	}
	if v.Absent != "" && strings.Contains(text, v.Absent) {
		return "unexpected " + v.Absent + " present", false
	}
	return "", true
}

func backup(path, content string) error {
	stamp := time.Now().Format("20060102-150405")
	bp := path + ".h9b-" + stamp
	if err := os.WriteFile(bp, []byte(content), 0o600); err != nil {
		return err
	}
	// Keep only the newest three backups per file.
	matches, _ := filepath.Glob(path + ".h9b-*")
	if len(matches) > 3 {
		sortStrings(matches)
		for _, m := range matches[:len(matches)-3] {
			_ = os.Remove(m)
		}
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Load reads and validates a bundle from disk.
//
// Validation here is structural only: it cannot know whether an anchor still
// exists on the target machine. That is what the `missing_anchor` result and the
// /v1/report telemetry are for.
func Load(path string) (*Bundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out Bundle
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out.Version < 1 {
		return nil, fmt.Errorf("bundle %s: version must be >= 1", path)
	}
	seen := make(map[string]bool, len(out.Recipes))
	for _, r := range out.Recipes {
		if r.ID == "" {
			return nil, fmt.Errorf("bundle %s: recipe without id", path)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("bundle %s: duplicate recipe id %q", path, r.ID)
		}
		seen[r.ID] = true
		if r.Target.Path == "" {
			return nil, fmt.Errorf("bundle %s/%s: empty target path", path, r.ID)
		}
		if len(r.Ops) == 0 {
			return nil, fmt.Errorf("bundle %s/%s: no ops", path, r.ID)
		}
		for _, op := range r.Ops {
			switch op.Op {
			case "replace", "insert_after", "append":
				if op.Find == "" {
					return nil, fmt.Errorf("bundle %s/%s: op %q needs find", path, r.ID, op.Op)
				}
			case "regex_replace":
				if op.Pattern == "" {
					return nil, fmt.Errorf("bundle %s/%s: regex_replace needs pattern", path, r.ID)
				}
			default:
				return nil, fmt.Errorf("bundle %s/%s: unknown op %q", path, r.ID, op.Op)
			}
		}
	}
	return &out, nil
}

// ExpandPath resolves the placeholders a recipe is allowed to use.
//
// Placeholders are resolved on the client, never on the server, so one bundle
// serves every OS and every install prefix without a per-customer payload.
// Router9Chunks resolves the 9router server-chunk directory.
//
// Global npm prefix varies by distro (/usr/lib vs /usr/local/lib), so the
// environment override exists for the odd box. Everything else is the default
// Debian layout.
func Router9Chunks() string {
	if p := os.Getenv("H9B_ROUTER9_CHUNKS"); p != "" {
		return p
	}
	return "/usr/lib/node_modules/9router/app/.next-cli-build/server/chunks"
}

func ExpandPath(p, home string) (string, error) {
	chunks := Router9Chunks()
	repl := map[string]string{
		"{home}":           home,
		"{hermes}":         filepath.Join(home, ".hermes"),
		"{hermes_agent}":   filepath.Join(home, ".hermes", "hermes-agent"),
		"{localappdata}":   os.Getenv("LOCALAPPDATA"),
		"{appdata}":        os.Getenv("APPDATA"),
		"{router9_chunks}": chunks,
	}
	if runtime.GOOS == "windows" && repl["{localappdata}"] == "" {
		repl["{localappdata}"] = filepath.Join(home, "AppData", "Local")
	}
	for k, v := range repl {
		p = strings.ReplaceAll(p, k, v)
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = filepath.Join(home, p[2:])
	}
	if strings.Contains(p, "%LOCALAPPDATA%") {
		p = strings.ReplaceAll(p, "%LOCALAPPDATA%", repl["{localappdata}"])
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("recipe: path must be absolute: %s", p)
	}
	return p, nil
}

func opLabel(op Op) string {
	if op.Label != "" {
		return op.Label
	}
	f := op.Find
	if f == "" {
		f = op.Pattern
	}
	if len(f) > 60 {
		f = f[:60] + "…"
	}
	return op.Op + ":" + f
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
