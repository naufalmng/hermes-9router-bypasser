// Package identity holds the server's long-term Ed25519 key.
//
// Why this exists: TLS alone cannot authenticate the payload channel when the
// server sits behind a TLS-terminating proxy (Cloudflare tunnel, corporate
// middlebox, hostile VPS provider). A relay can complete the X25519 handshake
// with its own ephemeral key and seal a payload the client will happily decrypt.
//
// The fix is a signature over the whole handshake transcript, made with a key
// that never leaves the server and whose public half is compiled into the
// client. Pinning then becomes defence-in-depth instead of the only control.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is the server's signing keypair.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	path string
}

// Load reads a key from path, creating one if the file does not exist.
//
// The generated key is written 0600 before it is used, so a crash between
// generate and persist cannot leave the server running with a key it will lose
// on restart.
func Load(path string) (*Identity, error) {
	if path == "" {
		return nil, errors.New("identity: empty path")
	}
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("identity: %s is %d bytes, want %d",
				path, len(raw), ed25519.PrivateKeySize)
		}
		priv := ed25519.PrivateKey(raw)
		return &Identity{priv: priv, pub: priv.Public().(ed25519.PublicKey), path: path}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, priv, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return &Identity{priv: priv, pub: pub, path: path}, nil
}

// PublicB64 is the value to embed in the client with
//
//	-ldflags "-X main.serverID=<value>"
func (i *Identity) PublicB64() string {
	return base64.StdEncoding.EncodeToString(i.pub)
}

// Sign returns the base64 signature over the handshake transcript.
//
// The transcript binds every field the client will act on: which licence, which
// client key, which server key, which nonce. Reordering or replaying a response
// against a different request changes the transcript and breaks the signature.
func (i *Identity) Sign(licenseID, clientEphPub, serverEphPub, nonceB64 string) string {
	msg := transcript(licenseID, clientEphPub, serverEphPub, nonceB64)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(i.priv, msg))
}

// Verify checks a signature from a server whose public key is known.
func Verify(pubB64, sigB64, licenseID, clientEphPub, serverEphPub, nonceB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("identity: bad server_id: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("identity: server_id is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("identity: bad sig: %w", err)
	}
	msg := transcript(licenseID, clientEphPub, serverEphPub, nonceB64)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return errors.New("identity: signature does not verify — server is not who it claims to be")
	}
	return nil
}

func transcript(licenseID, clientEphPub, serverEphPub, nonceB64 string) []byte {
	return []byte("h9b/v1|" + licenseID + "|" + clientEphPub + "|" + serverEphPub + "|" + nonceB64)
}
