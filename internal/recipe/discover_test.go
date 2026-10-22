package recipe

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Discovery is what makes the product work on a customer's machine at all. The
// Windows installer and the portable/Linux layout differ, and hardcoding either
// one means the other silently patches nothing.
func TestHermesRootFindsInstall(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".hermes", "hermes-agent")
	if err := os.MkdirAll(filepath.Join(root, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tools", "threat_patterns.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := HermesRoot(home); got != root {
		t.Fatalf("HermesRoot = %q, want %q", got, root)
	}
}

func TestHermesRootRejectsEmptyDecoy(t *testing.T) {
	home := t.TempDir()
	decoy := filepath.Join(home, ".hermes", "hermes-agent")
	if err := os.MkdirAll(decoy, 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory with the right name but no hermes files must not be accepted,
	// otherwise the client would report "patch failed" against an empty tree.
	if got := HermesRoot(home); got != "" {
		t.Fatalf("accepted an empty decoy: %q", got)
	}
}

func TestHermesRootHonoursOverride(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent", "prompt_builder.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("H9B_HERMES_ROOT", root)
	if got := HermesRoot(t.TempDir()); got != root {
		t.Fatalf("override ignored: %q", got)
	}
}

func TestExpandPathErrorsWhenHermesMissing(t *testing.T) {
	t.Setenv("H9B_HERMES_ROOT", "")
	home := t.TempDir()
	// Nothing installed under this home, and no override: the caller must get an
	// actionable error, not a relative path that resolves into the CWD.
	if _, err := ExpandPath("{hermes_agent}/tools/threat_patterns.py", home); err == nil {
		t.Fatal("expected an error when no hermes install exists")
	}
}

func TestRouter9ChunksFindsChunks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "5330.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("H9B_ROUTER9_CHUNKS", dir)
	if got := Router9Chunks(); got != dir {
		t.Fatalf("Router9Chunks = %q, want %q", got, dir)
	}
}

// Guard against a regression that only shows up on one OS: the candidates must
// actually be platform-appropriate.
func TestHermesCandidatesCoverBothLayouts(t *testing.T) {
	home := t.TempDir()
	// Windows installer layout, simulated through LOCALAPPDATA even on Linux.
	root := filepath.Join(home, "AppData", "Local", "hermes", "hermes-agent")
	if err := os.MkdirAll(filepath.Join(root, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tools", "threat_patterns.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	got := HermesRoot(home)
	if runtime.GOOS != "windows" {
		// On Linux the ~/.hermes candidate is tried first and does not exist, so
		// the LOCALAPPDATA one must win.
		if got != root {
			t.Fatalf("LOCALAPPDATA layout not found on %s: %q", runtime.GOOS, got)
		}
	} else if got != root {
		t.Fatalf("LOCALAPPDATA layout not found on windows: %q", got)
	}
}
