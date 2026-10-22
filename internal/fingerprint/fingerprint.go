// Package fingerprint produces a stable, privacy-preserving machine ID.
//
// It must survive a reboot and a package update but change when the machine
// changes, because it is what binds a CDK to one box. Raw identifiers never
// leave the host: only SHA-256(pepper || raw) is transmitted, and the pepper is
// compiled in per build so two customers cannot correlate their fingerprints
// against a leaked database.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// pepper is overridden at build time:
//
//	go build -ldflags "-X .../internal/fingerprint.pepper=<random>"
var pepper = "h9b-dev-pepper"

// raw collects the platform's stable machine identifier.
func raw() string {
	switch runtime.GOOS {
	case "windows":
		// MachineGuid is written at install time and survives updates.
		out, err := exec.Command("reg", "query",
			`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "MachineGuid") {
					f := strings.Fields(line)
					if len(f) >= 3 {
						return "win:" + f[len(f)-1]
					}
				}
			}
		}
		return "win:" + os.Getenv("COMPUTERNAME")
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						return "mac:" + strings.Trim(parts[1], " \"\n")
					}
				}
			}
		}
	default:
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil {
				if s := strings.TrimSpace(string(b)); s != "" {
					return "linux:" + s
				}
			}
		}
	}
	// Last resort: hostname + boot-independent bits. Weak, but never empty.
	h, _ := os.Hostname()
	return "fallback:" + h
}

// Get returns the hex fingerprint sent to the server.
func Get() string {
	sum := sha256.Sum256([]byte(pepper + "|" + raw()))
	return hex.EncodeToString(sum[:])[:32]
}

// SetPepper lets a build override the compiled-in pepper.
func SetPepper(p string) {
	if p != "" {
		pepper = p
	}
}
