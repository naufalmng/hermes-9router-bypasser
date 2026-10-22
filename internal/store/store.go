// Package store persists licences in a single JSON file.
//
// Deliberately boring: one file, one mutex, atomic rename on every write. At the
// volume this product will ever see (thousands of licences) a JSON file is
// faster to operate than Postgres and trivially backed up. Swap in a real DB
// when a second server needs to write.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apizen/h9b/internal/cdk"
	"github.com/apizen/h9b/internal/proto"
)

// Errors returned by Activate.
var (
	ErrUnknownCDK = errors.New("cdk not issued")
	ErrRevoked    = errors.New("licence revoked")
	ErrExpired    = errors.New("licence expired")
	ErrFingerprint = errors.New("licence bound to another machine")
	ErrSeats      = errors.New("seat limit reached")
)

// License is one issued key.
type License struct {
	ID        string `json:"id"`
	CDKHash   string `json:"cdk_hash"` // sha256(normalized cdk); plaintext is never stored
	CDKMask   string `json:"cdk_mask"` // H9B-AB***-***-***-XYZ for support
	FP        string `json:"fp"`
	Platform  string `json:"platform"`
	Tier      string `json:"tier"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
	RevokedAt int64  `json:"revoked_at,omitempty"`
	LastSeen  int64  `json:"last_seen"`
	Applies   int    `json:"applies"`
	BundleID  string `json:"bundle_id,omitempty"`
	LastReport []proto.RecipeResult `json:"last_report,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Store is the persisted state.
type Store struct {
	mu       sync.Mutex
	path     string
	Licenses map[string]*License `json:"licenses"`
	byCDK    map[string]string   `json:"-"`
	Version  int                 `json:"version"`
	mtime    time.Time           `json:"-"`
	size     int64               `json:"-"`
}

// HashCDK returns the lookup hash for a key.
func HashCDK(key string) string {
	sum := sha256.Sum256([]byte("h9b-cdk|" + cdk.Normalize(key)))
	return hex.EncodeToString(sum[:])
}

// Open loads (or creates) the store at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path, Licenses: map[string]*License{}, Version: 1}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("store: corrupt %s: %w", path, err)
		}
	case os.IsNotExist(err):
		if err := s.Save(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	s.reindex()
	if st, err := os.Stat(path); err == nil {
		s.mtime = st.ModTime()
		s.size = st.Size()
	}
	return s, nil
}

func (s *Store) reindex() {
	s.byCDK = make(map[string]string, len(s.Licenses))
	for id, l := range s.Licenses {
		s.byCDK[l.CDKHash] = id
	}
}

// Save writes atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.mtime = st.ModTime()
		s.size = st.Size()
	}
	return nil
}

// refreshLocked reloads the file if another process rewrote it.
//
// This exists because the operator workflow is `h9bd cdk new ...` while the
// server is running: two processes, one file. Without this, a freshly issued key
// is invisible until the server restarts, which looks exactly like a broken CDK
// to the customer. Caller must hold mu.
func (s *Store) refreshLocked() {
	st, err := os.Stat(s.path)
	if err != nil {
		return
	}
	if st.ModTime().Equal(s.mtime) && st.Size() == s.size {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var fresh Store
	if err := json.Unmarshal(raw, &fresh); err != nil {
		return // keep the in-memory copy rather than dropping every licence
	}
	s.Licenses = fresh.Licenses
	if s.Licenses == nil {
		s.Licenses = map[string]*License{}
	}
	s.Version = fresh.Version
	s.reindex()
	s.mtime = st.ModTime()
	s.size = st.Size()
}

// Issue registers a brand-new key. The plaintext key is returned once, for
// handing to the customer; only its hash is persisted.
func (s *Store) Issue(tier string, ttlDays int, note string) (string, *License, error) {
	key := cdk.Generate()
	now := time.Now()
	lic := &License{
		ID:        "lic_" + hex.EncodeToString(randomID())[:12],
		CDKHash:   HashCDK(key),
		CDKMask:   cdk.Mask(key),
		Tier:      tier,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(time.Duration(ttlDays) * 24 * time.Hour).Unix(),
		Note:      note,
	}
	s.mu.Lock()
	s.Licenses[lic.ID] = lic
	s.byCDK[lic.CDKHash] = lic.ID
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return "", nil, err
	}
	return key, lic, nil
}

// Lookup resolves a plaintext key to a licence without mutating it.
func (s *Store) Lookup(key string) (*License, error) {
	h := HashCDK(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byCDK[h]
	if !ok {
		return nil, ErrUnknownCDK
	}
	return s.Licenses[id], nil
}

// Get returns a licence by id.
func (s *Store) Get(id string) (*License, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	l, ok := s.Licenses[id]
	return l, ok
}

// Activate binds a key to a fingerprint. Re-activating the same machine is a
// no-op; a different fingerprint is refused, which is what makes a leaked key
// worthless to the second person who tries it.
func (s *Store) Activate(key, fp, platform string) (*License, error) {
	h := HashCDK(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	id, ok := s.byCDK[h]
	if !ok {
		return nil, ErrUnknownCDK
	}
	l := s.Licenses[id]
	if l.Revoked {
		return nil, ErrRevoked
	}
	now := time.Now().Unix()
	if l.ExpiresAt > 0 && now > l.ExpiresAt {
		return nil, ErrExpired
	}
	if l.FP == "" {
		l.FP = fp
		l.Platform = platform
	} else if l.FP != fp {
		return nil, ErrFingerprint
	}
	l.LastSeen = now
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return l, nil
}

// Touch records a payload fetch.
func (s *Store) Touch(id, bundleID string, results []proto.RecipeResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.Licenses[id]
	if !ok {
		return ErrUnknownCDK
	}
	l.LastSeen = time.Now().Unix()
	l.Applies++
	if bundleID != "" {
		l.BundleID = bundleID
	}
	if results != nil {
		l.LastReport = results
	}
	return s.saveLocked()
}

// Revoke disables a licence.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.Licenses[id]
	if !ok {
		return ErrUnknownCDK
	}
	l.Revoked = true
	l.RevokedAt = time.Now().Unix()
	return s.saveLocked()
}

// Rebind clears the machine fingerprint so the key can be activated again.
//
// This is the support lever for a re-imaged or replaced machine. It is
// deliberately operator-only and never reachable over HTTP.
func (s *Store) Rebind(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.Licenses[id]
	if !ok {
		return ErrUnknownCDK
	}
	l.FP = ""
	l.Platform = ""
	return s.saveLocked()
}

// Extend pushes the expiry out by days.
//
// Renewal is manual for now (the operator confirms the payment, then runs this),
// so it must be safe to repeat: extending from max(now, current expiry) means a
// customer who renews early does not lose the days they already paid for.
func (s *Store) Extend(id string, days int) (int64, error) {
	if days <= 0 {
		return 0, fmt.Errorf("extend: days must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	l, ok := s.Licenses[id]
	if !ok {
		return 0, ErrUnknownCDK
	}
	base := l.ExpiresAt
	if now := time.Now().Unix(); now > base {
		base = now
	}
	l.ExpiresAt = base + int64(days)*86400
	return l.ExpiresAt, s.saveLocked()
}

// SetNote records free-form operator context (order reference, buyer handle).
func (s *Store) SetNote(id, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.Licenses[id]
	if !ok {
		return ErrUnknownCDK
	}
	l.Note = note
	return s.saveLocked()
}

// List returns licences newest-first.
func (s *Store) List() []License {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	out := make([]License, 0, len(s.Licenses))
	for _, l := range s.Licenses {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// FindMask matches a partial mask or licence id for support lookups.
//
// Case-insensitive both ways: licence ids are lowercase, CDK masks are upper,
// and support staff paste whichever they have.
func (s *Store) FindMask(q string) []License {
	q = strings.ToUpper(strings.TrimSpace(q))
	var out []License
	for _, l := range s.List() {
		if strings.Contains(strings.ToUpper(l.CDKMask), q) ||
			strings.Contains(strings.ToUpper(l.ID), q) {
			out = append(out, l)
		}
	}
	return out
}

func randomID() []byte {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
