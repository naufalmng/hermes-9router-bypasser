package store

import (
	"errors"
	"testing"
	"time"

	"github.com/apizen/h9b/internal/fingerprint"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir + "/store.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key, _, err := s.Issue("pro", 30, "test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return s, key
}

func box(a, b, c string) map[string]string {
	return map[string]string{
		fingerprint.Machine: a,
		fingerprint.MAC:     b,
		fingerprint.Disk:    c,
	}
}

// The whole point of the lock: a key is worth nothing on a second machine, and
// stays worth something when one piece of hardware changes.
func TestActivateQuorum(t *testing.T) {
	s, key := newStore(t)
	orig := box("m1", "mac1", "d1")

	lic, err := s.Activate(key, "fp-orig", "linux", orig)
	if err != nil {
		t.Fatalf("first activate: %v", err)
	}
	if len(lic.HW) != 3 {
		t.Fatalf("bound with %d components, want 3", len(lic.HW))
	}

	// Same machine again: no-op, no error.
	if _, err := s.Activate(key, "fp-orig", "linux", orig); err != nil {
		t.Fatalf("re-activate same box: %v", err)
	}

	// NIC swapped. Two components agree, so the customer keeps working — but the
	// anchor must NOT move, or three small steps would walk the licence onto
	// different hardware.
	drifted := box("m1", "mac-NEW", "d1")
	lic, err = s.Activate(key, "fp-new", "linux", drifted)
	if err != nil {
		t.Fatalf("activate after NIC swap: %v", err)
	}
	if lic.HW[fingerprint.MAC] != "mac1" {
		t.Fatal("anchor moved: stored components must never be rewritten on drift")
	}
	// The original hardware is still the same box, so it must still work.
	if _, err := s.Activate(key, "fp-orig", "linux", orig); err != nil {
		t.Fatalf("original hardware must still activate: %v", err)
	}
	// Walking the binding must fail: two swaps in a row is 1 of 3 against the
	// anchor, so it needs an operator rebind.
	if _, err := s.Activate(key, "fp-walk", "linux", box("m1", "mac-NEW", "d-NEW")); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("drift walk must be refused, got %v", err)
	}

	// A different machine that copied machine-id: 1 of 3, below quorum.
	if _, err := s.Activate(key, "fp-clone", "linux", box("m1", "macX", "dX")); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("cloned machine-id must be refused, got %v", err)
	}

	// Nothing in common at all.
	if _, err := s.Activate(key, "fp-other", "linux", box("m2", "mac2", "d2")); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("different machine must be refused, got %v", err)
	}
}

// Rebinding must actually clear the hardware, otherwise "customer reinstalled
// Windows" support means nothing.
func TestRebindClearsHardware(t *testing.T) {
	s, key := newStore(t)
	if _, err := s.Activate(key, "fp1", "windows", box("m1", "mac1", "d1")); err != nil {
		t.Fatalf("activate: %v", err)
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("got %d licences", len(list))
	}
	if err := s.Rebind(list[0].ID); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	// A completely different machine can now take the licence.
	lic, err := s.Activate(key, "fp2", "windows", box("m9", "mac9", "d9"))
	if err != nil {
		t.Fatalf("activate after rebind: %v", err)
	}
	if lic.HW[fingerprint.Machine] != "m9" {
		t.Fatal("rebind did not take effect")
	}
}

// Licences issued before hardware components existed carry only a composite
// fingerprint. They must keep working, and must be upgraded in place.
func TestLegacyBindingUpgrades(t *testing.T) {
	s, key := newStore(t)
	list := s.List()
	id := list[0].ID
	// Simulate the old shape.
	s.mu.Lock()
	s.Licenses[id].FP = "fp-legacy"
	s.Licenses[id].HW = nil
	s.mu.Unlock()

	if _, err := s.Activate(key, "fp-different", "linux", box("m1", "mac1", "d1")); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("legacy licence must still check the composite fingerprint, got %v", err)
	}
	lic, err := s.Activate(key, "fp-legacy", "linux", box("m1", "mac1", "d1"))
	if err != nil {
		t.Fatalf("legacy activate: %v", err)
	}
	if len(lic.HW) != 3 {
		t.Fatal("legacy licence was not upgraded with hardware components")
	}
	// After the upgrade the quorum applies, so a clone is refused.
	if _, err := s.Activate(key, "fp-clone", "linux", box("m1", "x", "y")); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("upgraded licence must enforce quorum, got %v", err)
	}
}

func TestExpiredAndRevokedStillRefused(t *testing.T) {
	s, key := newStore(t)
	list := s.List()
	id := list[0].ID

	s.mu.Lock()
	s.Licenses[id].ExpiresAt = time.Now().Add(-time.Hour).Unix()
	s.mu.Unlock()
	if _, err := s.Activate(key, "fp", "linux", box("m", "mac", "d")); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired licence must be refused, got %v", err)
	}

	s.mu.Lock()
	s.Licenses[id].ExpiresAt = time.Now().Add(time.Hour).Unix()
	s.Licenses[id].Revoked = true
	s.mu.Unlock()
	if _, err := s.Activate(key, "fp", "linux", box("m", "mac", "d")); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked licence must be refused, got %v", err)
	}
}
