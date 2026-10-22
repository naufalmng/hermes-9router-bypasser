// Package cdk generates and validates licence keys (CDK).
//
// Format: H9B-XXXXX-XXXXX-XXXXX-XXX
//
//	16 data chars  = 10 random bytes in Crockford base32
//	 2 check chars = first 8 bits of SHA-256(data) in Crockford base32
//
// Crockford base32 drops I, L, O, U so keys survive being retyped from a
// screenshot or read aloud. Validation is offline: a typo never reaches the
// server, so a wrong key costs the customer nothing and costs us no traffic.
package cdk

import (
	"crypto/sha256"
	"crypto/rand"
	"strings"
)

// alphabet is Crockford base32 (no I, L, O, U).
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Prefix is the visible product tag on every key.
const Prefix = "H9B"

func encode(data []byte) string {
	var sb strings.Builder
	var buf uint32
	var bits uint
	for _, b := range data {
		buf = buf<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alphabet[(buf>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(buf<<(5-bits))&31])
	}
	return sb.String()
}

func decode(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s)*5/8)
	var buf uint32
	var bits uint
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(alphabet, s[i])
		if v < 0 {
			return nil, false
		}
		buf = buf<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, true
}

// Normalize uppercases, strips separators and the product prefix.
func Normalize(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimPrefix(s, Prefix)
	// Crockford confusables.
	s = strings.NewReplacer("I", "1", "L", "1", "O", "0", "U", "V").Replace(s)
	return s
}

// Generate returns a fresh formatted key.
func Generate() string {
	data := make([]byte, 10)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	body := encode(data) + encode(sum[:1])[:2]
	return Prefix + "-" + body[0:5] + "-" + body[5:10] + "-" + body[10:15] + "-" + body[15:18]
}

// Validate checks shape and checksum without touching the network.
func Validate(s string) bool {
	b := Normalize(s)
	if len(b) != 18 {
		return false
	}
	data, ok := decode(b[:16])
	if !ok || len(data) != 10 {
		return false
	}
	cs, ok := decode(b[16:18])
	if !ok || len(cs) != 1 {
		return false
	}
	sum := sha256.Sum256(data)
	return cs[0] == sum[0]
}

// Mask returns a log-safe rendering: H9B-AB***-***-***-XYZ.
func Mask(s string) string {
	n := Normalize(s)
	if len(n) < 8 {
		return "H9B-***"
	}
	return Prefix + "-" + n[0:2] + "***-***-***-" + n[len(n)-3:]
}
