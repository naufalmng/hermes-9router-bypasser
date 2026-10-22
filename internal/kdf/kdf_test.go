package kdf

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSealOpenRoundtrip(t *testing.T) {
	key := HKDF([]byte("secret"), []byte("salt"), []byte("info"), 32)
	msg := []byte("recipes go here")

	nonce, ct, err := Seal(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	k1 := HKDF([]byte("a"), nil, []byte("i"), 32)
	k2 := HKDF([]byte("b"), nil, []byte("i"), 32)
	nonce, ct, _ := Seal(k1, []byte("payload"))
	if _, err := Open(k2, nonce, ct); err == nil {
		t.Fatal("wrong key decrypted successfully")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := HKDF([]byte("a"), nil, []byte("i"), 32)
	nonce, ct, _ := Seal(key, []byte("payload"))
	ct[len(ct)-1] ^= 0xff
	if _, err := Open(key, nonce, ct); err == nil {
		t.Fatal("tampered ciphertext authenticated")
	}
}

// The full client/server agreement, exercised without a network.
func TestX25519AgreementMatches(t *testing.T) {
	curve := ecdh.X25519()
	client, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s1, err := client.ECDH(server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := server.ECDH(client.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("ECDH shared secrets differ")
	}

	nonce := Rand(16)
	salt := SHA256(nonce, []byte("lic_test"))
	ck := HKDF(s1, salt, []byte("h9b-payload-v1"), 32)
	sk := HKDF(s2, salt, []byte("h9b-payload-v1"), 32)
	if !bytes.Equal(ck, sk) {
		t.Fatal("derived keys differ")
	}

	msg := []byte(`{"recipes":[]}`)
	n, ct, err := Seal(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(ck, n, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("end-to-end mismatch: %q", got)
	}
}

func TestHKDFDeterministic(t *testing.T) {
	a := HKDF([]byte("s"), []byte("salt"), []byte("info"), 32)
	b := HKDF([]byte("s"), []byte("salt"), []byte("info"), 32)
	if !bytes.Equal(a, b) {
		t.Fatal("HKDF is not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(a))
	}
	// different info must produce a different key
	c := HKDF([]byte("s"), []byte("salt"), []byte("other"), 32)
	if bytes.Equal(a, c) {
		t.Fatal("info is not bound into the key")
	}
}
