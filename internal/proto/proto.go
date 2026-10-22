// Package proto holds the wire types shared by h9bd (server) and h9b (client).
//
// Nothing in here is secret: the client is a public binary, so every field name
// is assumed known to an attacker. Security lives in the payload (never shipped
// in the binary) and in the server-side signing key (never shipped at all).
package proto

// ActivateRequest binds a CDK to a machine fingerprint.
type ActivateRequest struct {
	CDK      string `json:"cdk"`
	FP       string `json:"fp"`
	Platform string `json:"platform"` // linux | windows | darwin
	Version  string `json:"version"`  // client build, for min-version gating
}

// ActivateResponse hands back a bearer token.
type ActivateResponse struct {
	LicenseID string `json:"license_id"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Tier      string `json:"tier"`
	ServerPub string `json:"server_pub"` // base64 X25519 static public key
	Notice    string `json:"notice,omitempty"`
}

// PayloadRequest asks for the sealed recipe bundle.
//
// EphPub is the client's ephemeral X25519 public key. The server replies with
// its own ephemeral key, so the content key exists only in the two processes'
// memory for the lifetime of one request. A recorded response cannot be
// decrypted later even with the client binary fully reversed, because the
// server's ephemeral private half is discarded after the response is written.
type PayloadRequest struct {
	Token    string `json:"token"`
	FP       string `json:"fp"`
	EphPub   string `json:"eph_pub"`
	Targets  []string `json:"targets,omitempty"` // requested recipe set, empty = all
	Nonce    string `json:"nonce"`
	ClientTS int64  `json:"client_ts"`
}

// PayloadResponse carries the sealed bundle.
type PayloadResponse struct {
	ServerEphPub string `json:"server_eph_pub"`
	Nonce        string `json:"nonce"` // base64 AEAD nonce
	CT           string `json:"ct"`    // base64 ciphertext
	BundleID     string `json:"bundle_id"`
	Version      int    `json:"version"`
	ExpiresAt    int64  `json:"expires_at"`
	RecipeIDs    []string `json:"recipe_ids"`
}

// ReportRequest is the client's post-apply telemetry. It is what makes anchor
// drift visible: when upstream rewrites a file we learn the exact anchor that
// disappeared, then push a new recipe to every licence without a new release.
type ReportRequest struct {
	Token   string       `json:"token"`
	FP      string       `json:"fp"`
	BundleID string      `json:"bundle_id"`
	Results []RecipeResult `json:"results"`
}

// RecipeResult is one recipe's outcome on the customer machine.
type RecipeResult struct {
	ID     string   `json:"id"`
	Status string   `json:"status"` // applied | already | missing_anchor | no_target | denied | error
	Detail string   `json:"detail,omitempty"`
	Missed []string `json:"missed,omitempty"`
}

// ErrorResponse is the uniform failure shape.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// HealthResponse is the liveness probe.
type HealthResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Bundle  int    `json:"bundle_version"`
	Recipes int    `json:"recipes"`
}
