// Package token mints and verifies the bearer token the client stores after
// activation.
//
// Stateless on purpose: the token carries the licence id, the bound fingerprint
// and an expiry, signed with HMAC-SHA256 under a key that exists only on the
// server. Revocation is the one thing a stateless token cannot do on its own,
// so the server still consults the store on every payload request — the token
// only proves "this client activated", never "this licence is still valid".
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Claims is the token body.
type Claims struct {
	LicenseID string `json:"lid"`
	FP        string `json:"fp"`
	Tier      string `json:"tier"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

var (
	// ErrMalformed means the token cannot be parsed.
	ErrMalformed = errors.New("token: malformed")
	// ErrSignature means the HMAC did not match.
	ErrSignature = errors.New("token: bad signature")
	// ErrExpired means the token is past its expiry.
	ErrExpired = errors.New("token: expired")
)

func sign(secret []byte, msg []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	return m.Sum(nil)
}

// Mint returns a compact signed token.
func Mint(secret []byte, c Claims) (string, error) {
	if c.IssuedAt == 0 {
		c.IssuedAt = time.Now().Unix()
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := base64.RawURLEncoding.EncodeToString(sign(secret, []byte(payload)))
	return payload + "." + mac, nil
}

// Verify parses and authenticates a token.
func Verify(secret []byte, tok string) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return c, ErrMalformed
	}
	want := sign(secret, []byte(parts[0]))
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, ErrMalformed
	}
	if !hmac.Equal(want, got) {
		return c, ErrSignature
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, ErrMalformed
	}
	if c.ExpiresAt > 0 && time.Now().Unix() > c.ExpiresAt {
		return c, ErrExpired
	}
	return c, nil
}
