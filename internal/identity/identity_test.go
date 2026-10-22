package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func newID(t *testing.T) *Identity {
	t.Helper()
	id, err := Load(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return id
}

func TestSignVerifyRoundtrip(t *testing.T) {
	id := newID(t)
	sig := id.Sign("lic_abc", "clientEph", "serverEph", "nonce")
	if err := Verify(id.PublicB64(), sig, "lic_abc", "clientEph", "serverEph", "nonce"); err != nil {
		t.Fatalf("honest signature rejected: %v", err)
	}
}

// Every field in the transcript must be load-bearing. If any one of them can be
// swapped without breaking the signature, a relay can splice a response from one
// request onto another.
func TestTranscriptIsBound(t *testing.T) {
	id := newID(t)
	sig := id.Sign("lic_abc", "clientEph", "serverEph", "nonce")

	cases := []struct {
		name                       string
		lic, cliEph, srvEph, nonce string
	}{
		{"other licence", "lic_other", "clientEph", "serverEph", "nonce"},
		{"other client key", "lic_abc", "clientEph2", "serverEph", "nonce"},
		{"other server key", "lic_abc", "clientEph", "serverEph2", "nonce"},
		{"other nonce", "lic_abc", "clientEph", "serverEph", "nonce2"},
	}
	for _, c := range cases {
		if err := Verify(id.PublicB64(), sig, c.lic, c.cliEph, c.srvEph, c.nonce); err == nil {
			t.Fatalf("%s: signature verified with a swapped field", c.name)
		}
	}
}

func TestWrongIdentityRejected(t *testing.T) {
	real := newID(t)
	attacker := newID(t)
	sig := attacker.Sign("lic_abc", "clientEph", "serverEph", "nonce")

	// The client embeds the real server's key; the attacker's signature must fail.
	if err := Verify(real.PublicB64(), sig, "lic_abc", "clientEph", "serverEph", "nonce"); err == nil {
		t.Fatal("attacker signature accepted under the real server identity")
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	id := newID(t)
	sig := id.Sign("lic_abc", "clientEph", "serverEph", "nonce")
	raw, _ := base64.StdEncoding.DecodeString(sig)
	raw[0] ^= 0x01
	bad := base64.StdEncoding.EncodeToString(raw)
	if err := Verify(id.PublicB64(), bad, "lic_abc", "clientEph", "serverEph", "nonce"); err == nil {
		t.Fatal("bit-flipped signature accepted")
	}
}

func TestMalformedInputsRejected(t *testing.T) {
	id := newID(t)
	sig := id.Sign("lic_abc", "clientEph", "serverEph", "nonce")

	if err := Verify("not-base64!!", sig, "lic_abc", "clientEph", "serverEph", "nonce"); err == nil {
		t.Fatal("garbage server id accepted")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if err := Verify(short, sig, "lic_abc", "clientEph", "serverEph", "nonce"); err == nil {
		t.Fatal("wrong-length server id accepted")
	}
	if err := Verify(id.PublicB64(), "!!notbase64", "lic_abc", "clientEph", "serverEph", "nonce"); err == nil {
		t.Fatal("garbage signature accepted")
	}
	if err := Verify(id.PublicB64(), "", "lic_abc", "clientEph", "serverEph", "nonce"); err == nil {
		t.Fatal("empty signature accepted")
	}
}

func TestLoadIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicB64() != b.PublicB64() {
		t.Fatal("identity changed across reloads — every shipped client would break")
	}
	_ = ed25519.PublicKeySize
}
