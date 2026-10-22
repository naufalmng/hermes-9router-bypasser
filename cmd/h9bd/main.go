// Command h9bd is the licence and payload server.
//
// It owns three secrets and nothing else:
//
//	token key    — signs activation tokens (never leaves the box)
//	static key   — X25519 identity, published so clients can pin a build
//	payloads/    — the actual patch recipes, plaintext only on this disk
//
// A compromised customer machine leaks, at worst, the recipes for the bundle it
// fetched, for the duration it was allowed to fetch them. It cannot mint keys,
// cannot extend a licence, and cannot serve another customer.
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apizen/h9b/internal/cdk"
	"github.com/apizen/h9b/internal/identity"
	"github.com/apizen/h9b/internal/kdf"
	"github.com/apizen/h9b/internal/proto"
	"github.com/apizen/h9b/internal/recipe"
	"github.com/apizen/h9b/internal/store"
	"github.com/apizen/h9b/internal/token"
)

const serverVersion = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "cdk":
		err = cmdCDK(os.Args[2:])
	case "lic":
		err = cmdLic(os.Args[2:])
	case "cert":
		err = cmdCert(os.Args[2:])
	case "payload":
		err = cmdPayload(os.Args[2:])
	case "version":
		fmt.Println(serverVersion)
	case "-h", "--help", "help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `h9bd — licence + payload server

  h9bd serve    -addr :8443 -store /var/lib/h9b/store.json -payloads ./payloads \
                -tls-cert cert.pem -tls-key key.pem -token-key <hex>
  h9bd cdk new  -n 10 -tier pro -days 30 -note "batch A"
  h9bd cdk list [-json]
  h9bd cdk revoke -id lic_xxx | -cdk H9B-...
  h9bd payload list -dir ./payloads
  h9bd payload check -dir ./payloads        # validate every recipe parses
  h9bd cert new -host h9b.apizen.my.id -out ./certs   # self-signed + SPKI pin
  h9bd version
`)
}

// ---------------------------------------------------------------- serve

type server struct {
	st        *store.Store
	tokenKey  []byte
	staticPub string
	id        *identity.Identity
	idPub     string
	mu        sync.Mutex
	lastFetch map[string]time.Time
	payloadDir string
	bundle    *recipe.Bundle
	bundleAt  time.Time
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	storePath := fs.String("store", "./data/store.json", "licence store path")
	payloadDir := fs.String("payloads", "./payloads", "recipe bundle directory")
	certFile := fs.String("tls-cert", "", "TLS certificate (empty = plain HTTP, dev only)")
	keyFile := fs.String("tls-key", "", "TLS private key")
	tokenKeyHex := fs.String("token-key", "", "HMAC key hex (empty = random per boot)")
	tokenKeyFile := fs.String("token-key-file", "", "file holding the HMAC key as hex (preferred over -token-key, keeps the key out of ps)")
	idKeyPath := fs.String("id-key", "./data/server.ed25519", "Ed25519 identity key (created if absent)")
	minGap := fs.Duration("min-gap", 3*time.Second, "minimum delay between payload fetches per machine")
	_ = fs.Parse(args)

	st, err := store.Open(*storePath)
	if err != nil {
		return err
	}
	s := &server{st: st, lastFetch: map[string]time.Time{}, payloadDir: *payloadDir}

	// Identity key: the client embeds its public half, so this file must survive
	// restarts and redeploys. Rotating it invalidates every shipped client.
	id, err := identity.Load(*idKeyPath)
	if err != nil {
		return err
	}
	s.id = id
	s.idPub = id.PublicB64()
	log.Printf("server identity %s (embed in client: -X main.serverID=%s)",
		*idKeyPath, s.idPub)
	if *tokenKeyFile != "" {
		raw, err := os.ReadFile(*tokenKeyFile)
		if err != nil {
			return fmt.Errorf("token-key-file: %w", err)
		}
		*tokenKeyHex = strings.TrimSpace(string(raw))
	}
	if *tokenKeyHex != "" {
		s.tokenKey, err = hex.DecodeString(*tokenKeyHex)
		if err != nil || len(s.tokenKey) < 32 {
			return fmt.Errorf("token-key must be >=32 bytes hex")
		}
	} else {
		s.tokenKey = kdf.Rand(32)
		log.Printf("WARN: no -token-key given, generated ephemeral key (tokens die on restart)")
	}
	if err := s.loadBundle(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/activate", s.handleActivate)
	mux.HandleFunc("/v1/payload", s.withGap(*minGap, s.handlePayload))
	mux.HandleFunc("/v1/report", s.handleReport)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Reload payloads on SIGHUP: publish a new recipe set without a restart,
	// so a customer's next `h9b apply` picks it up.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := s.loadBundle(); err != nil {
				log.Printf("reload failed: %v", err)
			} else {
				log.Printf("reloaded bundle %s v%d (%d recipes)", s.bundle.ID, s.bundle.Version, len(s.bundle.Recipes))
			}
		}
	}()

	log.Printf("h9bd %s listening on %s  bundle=%s v%d recipes=%d",
		serverVersion, *addr, s.bundle.ID, s.bundle.Version, len(s.bundle.Recipes))
	if *certFile != "" && *keyFile != "" {
		return srv.ListenAndServeTLS(*certFile, *keyFile)
	}
	log.Printf("WARN: serving plain HTTP — put a TLS terminator in front before production")
	return srv.ListenAndServe()
}

// loadBundle merges every *.json recipe file into one versioned bundle.
func (s *server) loadBundle() error {
	entries, err := os.ReadDir(s.payloadDir)
	if err != nil {
		return fmt.Errorf("payloads dir: %w", err)
	}
	merged := &recipe.Bundle{ID: "bundle-" + time.Now().Format("20060102"), Version: 0}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(s.payloadDir, name))
		if err != nil {
			return err
		}
		b, err := recipe.Parse(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if b.Version > merged.Version {
			merged.Version = b.Version
		}
		merged.Recipes = append(merged.Recipes, b.Recipes...)
	}
	if merged.Version == 0 {
		merged.Version = 1
	}
	s.mu.Lock()
	s.bundle = merged
	s.bundleAt = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	v, n := s.bundle.Version, len(s.bundle.Recipes)
	s.mu.Unlock()
	writeJSON(w, 200, proto.HealthResponse{OK: true, Version: serverVersion, Bundle: v, Recipes: n})
}

func (s *server) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "method")
		return
	}
	var req proto.ActivateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", "bad_request")
		return
	}
	if !cdk.Validate(req.CDK) {
		writeErr(w, 400, "malformed key", "bad_cdk")
		return
	}
	if len(req.FP) < 16 {
		writeErr(w, 400, "missing machine fingerprint", "bad_fp")
		return
	}
	lic, err := s.st.Activate(req.CDK, req.FP, req.Platform)
	if err != nil {
		code := "refused"
		switch err {
		case store.ErrUnknownCDK:
			code = "unknown_cdk"
		case store.ErrRevoked:
			code = "revoked"
		case store.ErrExpired:
			code = "expired"
		case store.ErrFingerprint:
			code = "bound_elsewhere"
		}
		log.Printf("activate refused key=%s fp=%s code=%s", cdk.Mask(req.CDK), short(req.FP), code)
		writeErr(w, 403, err.Error(), code)
		return
	}
	tok, err := token.Mint(s.tokenKey, token.Claims{
		LicenseID: lic.ID, FP: lic.FP, Tier: lic.Tier,
		IssuedAt: time.Now().Unix(), ExpiresAt: lic.ExpiresAt,
	})
	if err != nil {
		writeErr(w, 500, "token mint failed", "internal")
		return
	}
	log.Printf("activate ok key=%s lic=%s platform=%s", lic.CDKMask, lic.ID, req.Platform)
	writeJSON(w, 200, proto.ActivateResponse{
		LicenseID: lic.ID,
		Token:     tok,
		ExpiresAt: lic.ExpiresAt,
		Tier:      lic.Tier,
		ServerPub: s.staticPub,
	})
}

func (s *server) withGap(gap time.Duration, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			FP string `json:"fp"`
		}
		// Best-effort: the body is re-read by the handler, so peek via header too.
		fp := r.Header.Get("X-H9B-FP")
		if fp == "" {
			fp = req.FP
		}
		s.mu.Lock()
		last, seen := s.lastFetch[fp]
		if seen && time.Since(last) < gap {
			s.mu.Unlock()
			writeErr(w, 429, "too many fetches, slow down", "rate_limited")
			return
		}
		s.lastFetch[fp] = time.Now()
		s.mu.Unlock()
		h(w, r)
	}
}

func (s *server) handlePayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "method")
		return
	}
	var req proto.PayloadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", "bad_request")
		return
	}
	claims, err := token.Verify(s.tokenKey, req.Token)
	if err != nil {
		writeErr(w, 401, err.Error(), "bad_token")
		return
	}
	lic, ok := s.st.Get(claims.LicenseID)
	if !ok || lic.Revoked {
		writeErr(w, 403, "licence revoked", "revoked")
		return
	}
	if lic.ExpiresAt > 0 && time.Now().Unix() > lic.ExpiresAt {
		writeErr(w, 403, "licence expired", "expired")
		return
	}
	if lic.FP != req.FP || claims.FP != req.FP {
		writeErr(w, 403, "fingerprint mismatch", "bound_elsewhere")
		return
	}

	cliPubRaw, err := base64.StdEncoding.DecodeString(req.EphPub)
	if err != nil || len(cliPubRaw) != 32 {
		writeErr(w, 400, "bad ephemeral key", "bad_eph")
		return
	}
	cliPub, err := ecdh.X25519().NewPublicKey(cliPubRaw)
	if err != nil {
		writeErr(w, 400, "bad ephemeral key", "bad_eph")
		return
	}
	// Ephemeral server half: created here, dropped when this handler returns.
	// Nothing on disk can ever decrypt a captured response afterwards.
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		writeErr(w, 500, "keygen failed", "internal")
		return
	}
	shared, err := eph.ECDH(cliPub)
	if err != nil {
		writeErr(w, 400, "ecdh failed", "bad_eph")
		return
	}

	s.mu.Lock()
	bundle := s.bundle
	s.mu.Unlock()

	// Tier/platform filtering happens server-side: the client never receives a
	// recipe it is not entitled to, so a memory dump shows only what was bought.
	filtered := &recipe.Bundle{ID: bundle.ID, Version: bundle.Version}
	for _, rec := range bundle.Recipes {
		if len(req.Targets) > 0 && !containsStr(req.Targets, rec.ID) {
			continue
		}
		filtered.Recipes = append(filtered.Recipes, rec)
	}
	plain, err := json.Marshal(filtered)
	if err != nil {
		writeErr(w, 500, "marshal failed", "internal")
		return
	}

	salt := kdf.SHA256([]byte(req.Nonce), []byte(lic.ID))
	key := kdf.HKDF(shared, salt, []byte("h9b-payload-v1"), 32)
	nonce, ct, err := kdf.Seal(key, plain)
	if err != nil {
		writeErr(w, 500, "seal failed", "internal")
		return
	}

	ids := make([]string, 0, len(filtered.Recipes))
	for _, rec := range filtered.Recipes {
		ids = append(ids, rec.ID)
	}
	_ = s.st.Touch(lic.ID, filtered.ID, nil)
	log.Printf("payload served lic=%s bundle=%s v%d recipes=%d bytes=%d",
		lic.ID, filtered.ID, filtered.Version, len(ids), len(ct))

	serverEphB64 := base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes())
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	// Sign the transcript last: every field the client will act on is now fixed.
	sig := ""
	if s.id != nil {
		sig = s.id.Sign(lic.ID, req.EphPub, serverEphB64, req.Nonce)
	}

	writeJSON(w, 200, proto.PayloadResponse{
		ServerEphPub: serverEphB64,
		Nonce:        nonceB64,
		CT:           base64.StdEncoding.EncodeToString(ct),
		ServerID:     s.idPub,
		Sig:          sig,
		BundleID:     filtered.ID,
		Version:      filtered.Version,
		ExpiresAt:    lic.ExpiresAt,
		RecipeIDs:    ids,
	})
}

func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "method")
		return
	}
	var req proto.ReportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", "bad_request")
		return
	}
	claims, err := token.Verify(s.tokenKey, req.Token)
	if err != nil {
		writeErr(w, 401, err.Error(), "bad_token")
		return
	}
	if claims.FP != req.FP {
		writeErr(w, 403, "fingerprint mismatch", "bound_elsewhere")
		return
	}
	_ = s.st.Touch(claims.LicenseID, req.BundleID, req.Results)
	for _, res := range req.Results {
		if res.Status == "missing_anchor" {
			log.Printf("ANCHOR DRIFT lic=%s recipe=%s missed=%v", claims.LicenseID, res.ID, res.Missed)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- cdk

func cmdCDK(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cdk: need new|list|revoke")
	}
	fs := flag.NewFlagSet("cdk", flag.ExitOnError)
	storePath := fs.String("store", "./data/store.json", "licence store path")
	switch args[0] {
	case "new":
		n := fs.Int("n", 1, "how many keys")
		tier := fs.String("tier", "pro", "tier label")
		days := fs.Int("days", 30, "validity in days")
		note := fs.String("note", "", "internal note")
		_ = fs.Parse(args[1:])
		st, err := store.Open(*storePath)
		if err != nil {
			return err
		}
		for i := 0; i < *n; i++ {
			key, lic, err := st.Issue(*tier, *days, *note)
			if err != nil {
				return err
			}
			fmt.Printf("%s\t%s\t%s\texpires %s\n", key, lic.ID, lic.Tier,
				time.Unix(lic.ExpiresAt, 0).Format("2006-01-02"))
		}
		return nil
	case "list":
		asJSON := fs.Bool("json", false, "json output")
		_ = fs.Parse(args[1:])
		st, err := store.Open(*storePath)
		if err != nil {
			return err
		}
		list := st.List()
		if *asJSON {
			b, _ := json.MarshalIndent(list, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("%-20s %-18s %-8s %-10s %-8s %s\n", "MASK", "ID", "TIER", "EXPIRES", "APPLIES", "STATE")
		for _, l := range list {
			state := "active"
			if l.Revoked {
				state = "REVOKED"
			} else if l.ExpiresAt > 0 && time.Now().Unix() > l.ExpiresAt {
				state = "expired"
			}
			fmt.Printf("%-20s %-18s %-8s %-10s %-8d %s\n", l.CDKMask, l.ID, l.Tier,
				time.Unix(l.ExpiresAt, 0).Format("2006-01-02"), l.Applies, state)
		}
		return nil
	case "revoke":
		id := fs.String("id", "", "licence id")
		key := fs.String("cdk", "", "plaintext key")
		_ = fs.Parse(args[1:])
		st, err := store.Open(*storePath)
		if err != nil {
			return err
		}
		if *key != "" {
			lic, err := st.Lookup(*key)
			if err != nil {
				return err
			}
			*id = lic.ID
		}
		if *id == "" {
			return fmt.Errorf("revoke: need -id or -cdk")
		}
		if err := st.Revoke(*id); err != nil {
			return err
		}
		fmt.Println("revoked", *id)
		return nil
	}
	return fmt.Errorf("cdk: unknown subcommand %q", args[0])
}

// ---------------------------------------------------------------- lic

// cmdLic is the support surface: who is bound where, and how to move them.
func cmdLic(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("lic: need list|rebind|show")
	}
	fs := flag.NewFlagSet("lic", flag.ExitOnError)
	storePath := fs.String("store", "./data/store.json", "licence store path")
	asJSON := fs.Bool("json", false, "json output")
	switch args[0] {
	case "list":
		_ = fs.Parse(args[1:])
		st, err := store.Open(*storePath)
		if err != nil {
			return err
		}
		list := st.List()
		if *asJSON {
			b, _ := json.MarshalIndent(list, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("%-20s %-18s %-10s %-10s %-7s %s\n",
			"MASK", "ID", "TIER", "EXPIRES", "APPLY", "BOUND / STATE")
		for _, l := range list {
			state := "unbound"
			if l.FP != "" {
				state = l.Platform + " " + l.FP[:8]
			}
			if l.Revoked {
				state = "REVOKED"
			} else if l.ExpiresAt > 0 && time.Now().Unix() > l.ExpiresAt {
				state = "expired"
			}
			fmt.Printf("%-20s %-18s %-10s %-10s %-7d %s\n", l.CDKMask, l.ID, l.Tier,
				time.Unix(l.ExpiresAt, 0).Format("2006-01-02"), l.Applies, state)
		}
		return nil
	case "show":
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			return fmt.Errorf("lic show: need licence id or mask")
		}
		st, err := store.Open(*storePath)
		if err != nil {
			return err
		}
		hits := st.FindMask(fs.Arg(0))
		if len(hits) == 0 {
			return fmt.Errorf("no licence matching %q", fs.Arg(0))
		}
		b, _ := json.MarshalIndent(hits, "", "  ")
		fmt.Println(string(b))
		return nil
	case "rebind":
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			return fmt.Errorf("lic rebind: need licence id")
		}
		st, err := store.Open(*storePath)
		if err != nil {
			return err
		}
		if err := st.Rebind(fs.Arg(0)); err != nil {
			return err
		}
		fmt.Println("rebound", fs.Arg(0), "— customer must run: h9b activate <same cdk>")
		return nil
	}
	return fmt.Errorf("lic: unknown subcommand %q", args[0])
}

// ---------------------------------------------------------------- payload
func cmdPayload(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("payload: need list|check")
	}
	fs := flag.NewFlagSet("payload", flag.ExitOnError)
	dir := fs.String("dir", "./payloads", "recipe dir")
	_ = fs.Parse(args[1:])
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	total := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(*dir, e.Name()))
		if err != nil {
			return err
		}
		b, err := recipe.Parse(raw)
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", e.Name(), err)
			continue
		}
		total += len(b.Recipes)
		if args[0] == "list" {
			fmt.Printf("%s  v%d  %d recipes\n", e.Name(), b.Version, len(b.Recipes))
			for _, r := range b.Recipes {
				fmt.Printf("  - %-28s %s\n", r.ID, r.Title)
			}
		} else {
			fmt.Printf("OK   %s  v%d  %d recipes\n", e.Name(), b.Version, len(b.Recipes))
		}
	}
	fmt.Printf("total recipes: %d\n", total)
	return nil
}

// ---------------------------------------------------------------- cert

func cmdCert(args []string) error {
	if len(args) == 0 || args[0] != "new" {
		return fmt.Errorf("cert: need new")
	}
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	host := fs.String("host", "h9b.apizen.my.id", "hostname")
	out := fs.String("out", "./certs", "output dir")
	days := fs.Int("days", 365, "validity")
	_ = fs.Parse(args[1:])

	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: *host, Organization: []string{"H9B"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{*host},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(*host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	certPath := filepath.Join(*out, "cert.pem")
	keyPath := filepath.Join(*out, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	fmt.Printf("cert: %s\nkey:  %s\nSPKI pin (embed in client -X main.pin):\n%s\n", certPath, keyPath, hex.EncodeToString(pin[:]))
	return nil
}

// ---------------------------------------------------------------- helpers

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/healthz" {
			log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg, tag string) {
	writeJSON(w, code, proto.ErrorResponse{Error: msg, Code: tag})
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
