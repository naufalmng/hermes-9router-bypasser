// Package kdf implements HKDF-SHA256 plus AES-256-GCM sealing.
//
// Deliberately dependency-free (Go 1.22 has no crypto/hkdf in stdlib) so the
// whole tree builds offline with `go build` and cross-compiles to Windows with
// CGO_ENABLED=0.
package kdf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Extract derives a pseudorandom key from secret and salt (RFC 5869 step 1).
func extract(secret, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(secret)
	return m.Sum(nil)
}

// Expand stretches prk to n bytes (RFC 5869 step 2).
func expand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// HKDF is extract-then-expand.
func HKDF(secret, salt, info []byte, n int) []byte {
	return expand(extract(secret, salt), info, n)
}

// Seal encrypts plaintext with AES-256-GCM under a fresh random nonce.
func Seal(key, plaintext []byte) (nonce, ct []byte, err error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

// Open decrypts a sealed blob.
func Open(key, nonce, ct []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("kdf: key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Rand returns n cryptographically random bytes.
func Rand(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// SHA256 is a short alias used across the tree.
func SHA256(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
