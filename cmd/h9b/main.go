// Command h9b is the customer-facing CLI.
//
// Build with garble so the strings and control flow are not readable:
//
//	garble -tiny -literals build -ldflags "-s -w -X main.pin=<spki>" ./cmd/h9b
//
// The binary holds no patch data. It holds an interpreter and a TLS pin.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/apizen/h9b/internal/cdk"
	"github.com/apizen/h9b/internal/fingerprint"
	"github.com/apizen/h9b/internal/kdf"
	"github.com/apizen/h9b/internal/proto"
	"github.com/apizen/h9b/internal/recipe"
)

// clientVersion is a var so -ldflags "-X main.clientVersion=..." can stamp it
// at release time. A const would be inlined and un-settable.
var clientVersion = "0.1.0-dev"

// pin is the SPKI SHA-256 of the server certificate, injected at build time.
// Empty means "no pinning" and is only acceptable for local testing.
var pin = ""

// caFile is an extra trust anchor, for deployments that are not yet behind a
// public CA. Set with --ca or H9B_CA. Pinning still applies on top of it.
var caFile = os.Getenv("H9B_CA")

type config struct {
	Server    string `json:"server"`
	Token     string `json:"token"`
	LicenseID string `json:"license_id"`
	FP        string `json:"fp"`
	Tier      string `json:"tier"`
	ExpiresAt int64  `json:"expires_at"`
	LastApply int64  `json:"last_apply"`
	BundleID  string `json:"bundle_id,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "activate":
		err = cmdActivate(os.Args[2:])
	case "apply":
		err = cmdApply(os.Args[2:])
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "deactivate":
		err = cmdDeactivate(os.Args[2:])
	case "rollback":
		err = cmdRollback(os.Args[2:])
	case "version":
		fmt.Println(clientVersion)
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
	fmt.Fprint(os.Stderr, `h9b — runtime patch client

  h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX [--server URL]
  h9b apply [--dry-run] [--only recipe-id] [--verbose]
  h9b watch [--interval 60] [--interval 60]
  h9b status
  h9b doctor
  h9b rollback [--all] [--dry-run]
  h9b deactivate
  h9b version
`)
}

// ---------------------------------------------------------------- config

func configPath() string {
	if p := os.Getenv("H9B_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".h9b", "config.json")
}

func loadConfig() (*config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("not activated — run: h9b activate <KEY>")
		}
		return nil, err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveConfig(c *config) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// ---------------------------------------------------------------- http

func newClient(insecure bool) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		if pemBytes, err := os.ReadFile(caFile); err == nil {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pemBytes)
			cfg.RootCAs = pool
		}
	}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	if pin != "" {
		want := strings.ToLower(strings.TrimSpace(pin))
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("tls: no peer certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("tls: certificate pin mismatch")
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true},
	}
}

func post(c *http.Client, url, fp string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "h9b/"+clientVersion+" "+runtime.GOOS+"/"+runtime.GOARCH)
	req.Header.Set("X-H9B-FP", fp)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e proto.ErrorResponse
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s (%s)", e.Error, e.Code)
		}
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.Unmarshal(raw, out)
}

// ---------------------------------------------------------------- commands

func cmdActivate(args []string) error {
	args = rotateLeadingPositional(args)
	fs := flag.NewFlagSet("activate", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "server base URL")
	insecure := fs.Bool("insecure", false, "skip certificate verification (testing only)")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return errors.New("activate: need a key")
	}
	key := fs.Arg(0)
	if !cdk.Validate(key) {
		return errors.New("activate: key is malformed (check for typos)")
	}
	fp := fingerprint.Get()
	var out proto.ActivateResponse
	if err := post(newClient(*insecure), strings.TrimRight(*server, "/")+"/v1/activate", fp, proto.ActivateRequest{
		CDK: key, FP: fp, Platform: runtime.GOOS, Version: clientVersion,
	}, &out); err != nil {
		return err
	}
	if err := saveConfig(&config{
		Server: *server, Token: out.Token, LicenseID: out.LicenseID,
		FP: fp, Tier: out.Tier, ExpiresAt: out.ExpiresAt,
	}); err != nil {
		return err
	}
	fmt.Printf("activated  %s  tier=%s  expires=%s\n", out.LicenseID, out.Tier,
		time.Unix(out.ExpiresAt, 0).Format("2006-01-02"))
	if out.Notice != "" {
		fmt.Println(out.Notice)
	}
	return nil
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	dry := fs.Bool("dry-run", false, "report only, write nothing")
	only := fs.String("only", "", "comma-separated recipe ids")
	verbose := fs.Bool("verbose", false, "per-op detail")
	insecure := fs.Bool("insecure", false, "skip certificate verification")
	server := fs.String("server", "", "override server URL")
	_ = fs.Parse(args)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if *server != "" {
		cfg.Server = *server
	}
	bundle, err := fetchBundle(cfg, *insecure)
	if err != nil {
		return err
	}
	opts := recipe.Options{Platform: runtime.GOOS, DryRun: *dry}
	if *only != "" {
		opts.Only = strings.Split(*only, ",")
	}
	if *verbose {
		opts.Log = func(f string, a ...any) { fmt.Printf(f+"\n", a...) }
	}
	results := recipe.Apply(bundle, opts)

	applied, already, failed := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "applied":
			applied++
			fmt.Printf("  + %-30s %s\n", r.ID, r.Detail)
		case "already", "skipped":
			already++
			if *verbose {
				fmt.Printf("  = %-30s %s\n", r.ID, r.Detail)
			}
		case "dry_run":
			applied++
			fmt.Printf("  ~ %-30s %s\n", r.ID, r.Detail)
		default:
			failed++
			fmt.Printf("  ! %-30s %s %v\n", r.ID, r.Status, r.Missed)
		}
	}
	fmt.Printf("\nbundle %s v%d — %d applied, %d already, %d failed\n",
		bundle.ID, bundle.Version, applied, already, failed)

	// Report back so anchor drift shows up on the server, not in a support ticket.
	if !*dry {
		reportResults(cfg, *insecure, bundle.ID, results)
		cfg.LastApply = time.Now().Unix()
		cfg.BundleID = bundle.ID
		_ = saveConfig(cfg)
	}
	if failed > 0 {
		return fmt.Errorf("%d recipe(s) did not apply", failed)
	}
	return nil
}

func fetchBundle(cfg *config, insecure bool) (*recipe.Bundle, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := kdf.Rand(16)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	var out proto.PayloadResponse
	if err := post(newClient(insecure), strings.TrimRight(cfg.Server, "/")+"/v1/payload", cfg.FP, proto.PayloadRequest{
		Token: cfg.Token, FP: cfg.FP,
		EphPub:  base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:   nonceB64,
		ClientTS: time.Now().Unix(),
	}, &out); err != nil {
		return nil, err
	}
	srvRaw, err := base64.StdEncoding.DecodeString(out.ServerEphPub)
	if err != nil || len(srvRaw) != 32 {
		return nil, errors.New("bad server ephemeral key")
	}
	srvPub, err := ecdh.X25519().NewPublicKey(srvRaw)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(srvPub)
	if err != nil {
		return nil, err
	}
	// Salt binds the key to this licence and this request nonce. Both sides hash
	// the base64 rendering of the nonce, not the raw bytes, so the derivation is
	// unambiguous across the wire.
	salt := kdf.SHA256([]byte(nonceB64), []byte(cfg.LicenseID))
	key := kdf.HKDF(shared, salt, []byte("h9b-payload-v1"), 32)
	ct, err := base64.StdEncoding.DecodeString(out.CT)
	if err != nil {
		return nil, err
	}
	ns, err := base64.StdEncoding.DecodeString(out.Nonce)
	if err != nil {
		return nil, err
	}
	plain, err := kdf.Open(key, ns, ct)
	if err != nil {
		return nil, fmt.Errorf("payload decrypt failed (wrong server key or tampered response): %w", err)
	}
	return recipe.Parse(plain)
}

func reportResults(cfg *config, insecure bool, bundleID string, results []recipe.Result) {
	pr := make([]proto.RecipeResult, 0, len(results))
	for _, r := range results {
		pr = append(pr, proto.RecipeResult{ID: r.ID, Status: r.Status, Detail: r.Detail, Missed: r.Missed})
	}
	_ = post(newClient(insecure), strings.TrimRight(cfg.Server, "/")+"/v1/report", cfg.FP,
		proto.ReportRequest{Token: cfg.Token, FP: cfg.FP, BundleID: bundleID, Results: pr}, &struct{}{})
}

func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Int("interval", 60, "seconds between checks")
	insecure := fs.Bool("insecure", false, "skip certificate verification")
	_ = fs.Parse(args)
	if *interval < 10 {
		return errors.New("watch: interval must be >= 10s")
	}
	fmt.Printf("watching — re-applying every %ds (ctrl-c to stop)\n", *interval)
	for {
		if err := cmdApply([]string{"--insecure=" + boolStr(*insecure)}); err != nil {
			fmt.Fprintf(os.Stderr, "%s  %v\n", time.Now().Format("15:04:05"), err)
		}
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

func cmdStatus(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fmt.Printf("license   %s\ntier      %s\nexpires   %s\nserver    %s\nmachine   %s\n",
		cfg.LicenseID, cfg.Tier,
		time.Unix(cfg.ExpiresAt, 0).Format("2006-01-02 15:04"),
		cfg.Server, cfg.FP)
	if cfg.LastApply > 0 {
		fmt.Printf("last apply %s (%s)\n",
			time.Unix(cfg.LastApply, 0).Format("2006-01-02 15:04"), cfg.BundleID)
	}
	return nil
}

func cmdDoctor(args []string) error {
	fmt.Printf("client     %s\ngo/runtime %s %s/%s\nconfig     %s\n",
		clientVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH, configPath())
	fmt.Printf("machine    %s\n", fingerprint.Get())
	if pin == "" {
		fmt.Println("tls pin    NOT SET (dev build)")
	} else {
		fmt.Printf("tls pin    %s…\n", pin[:16])
	}
	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("license    none")
		return nil
	}
	fmt.Printf("server     %s\n", cfg.Server)
	if _, err := fetchBundle(cfg, true); err != nil {
		fmt.Printf("fetch      FAILED: %v\n", err)
	} else {
		fmt.Println("fetch      ok")
	}
	return nil
}

func cmdDeactivate(args []string) error {
	p := configPath()
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("local token removed (licence stays bound to this machine on the server)")
	return nil
}

// ---------------------------------------------------------------- helpers

func defaultServer() string {
	if s := os.Getenv("H9B_SERVER"); s != "" {
		return s
	}
	return "https://h9b.apizen.my.id"
}

// cmdRollback restores the newest .h9b-<ts> backup for every patched file.
//
// This is the safety net that makes the product sellable: a customer who does
// not like the result gets their stock install back with one command, no
// reinstall, no support ticket.
func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	dry := fs.Bool("dry-run", false, "show what would be restored")
	all := fs.Bool("all", false, "also scan the 9router chunks directory (needs root)")
	verbose := fs.Bool("verbose", false, "print every file considered")
	fs.Parse(args)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	roots := []string{filepath.Join(home, ".hermes", "hermes-agent")}
	if *all {
		roots = append(roots, recipe.Router9Chunks())
	}

	// original path -> newest backup path
	newest := map[string]string{}
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := d.Name()
			i := strings.LastIndex(base, ".h9b-")
			if i < 0 {
				return nil
			}
			stamp := base[i+len(".h9b-"):]
			if len(stamp) != 15 || stamp[8] != '-' {
				return nil
			}
			orig := filepath.Join(filepath.Dir(p), base[:i])
			if cur, ok := newest[orig]; !ok || filepath.Base(cur) < base {
				newest[orig] = p
			}
			if *verbose {
				fmt.Printf("  ? %s  <- %s\n", orig, base)
			}
			return nil
		})
	}
	if len(newest) == 0 {
		return errors.New("no .h9b-* backups found (nothing to roll back)")
	}

	var restored, failed int
	for orig, bak := range newest {
		if *dry {
			fmt.Printf("  would restore %s  <- %s\n", orig, filepath.Base(bak))
			restored++
			continue
		}
		data, err := os.ReadFile(bak)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s: %v\n", orig, err)
			failed++
			continue
		}
		info, _ := os.Stat(orig)
		mode := os.FileMode(0o644)
		if info != nil {
			mode = info.Mode().Perm()
		}
		if err := os.WriteFile(orig, data, mode); err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s: %v (try sudo)\n", orig, err)
			failed++
			continue
		}
		os.Remove(bak)
		fmt.Printf("  - restored %s\n", orig)
		restored++
	}
	verb := "restored"
	if *dry {
		verb = "would restore"
	}
	fmt.Printf("\n%s %d file(s), %d failed\n", verb, restored, failed)
	if failed > 0 {
		return fmt.Errorf("%d file(s) could not be restored", failed)
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// rotateLeadingPositional lets `h9b activate KEY --server URL` work.
//
// Go's flag package stops parsing at the first non-flag token, so a key typed
// before the flags would silently drop every flag after it. Customers type the
// key first; the CLI should accept that instead of pretending the flags do not
// exist.
func rotateLeadingPositional(args []string) []string {
	i := 0
	for i < len(args) && !strings.HasPrefix(args[i], "-") {
		i++
	}
	if i == 0 || i == len(args) {
		return args
	}
	out := append([]string{}, args[i:]...)
	return append(out, args[:i]...)
}
