// Package fingerprint produces a stable, privacy-preserving machine ID and a
// small set of hardware components used to bind a CDK to one box.
//
// Raw identifiers never leave the host: only SHA-256(pepper || name || raw) is
// transmitted. The pepper is a build-time secret, so a leaked licence store
// cannot be turned into a rainbow table against the customer's hardware.
//
// # Why components instead of one value
//
// A single value is brittle in both directions. Hash only the MAC and a customer
// who plugs in a USB dock, toggles Wi-Fi, or installs a VPN client gets locked
// out of a licence they paid for. Hash only /etc/machine-id and the lock is
// worthless on Linux and in a VM: that file is root-writable and is copied
// verbatim when someone clones an image, which is exactly the sharing the lock
// exists to stop.
//
// So three independent components are collected and the server requires a
// quorum: at least two must match. Cloning machine-id no longer helps, because
// the clone has different NICs and a different disk serial. Swapping a NIC no
// longer hurts, because the machine id and disk serial still agree.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// pepper is overridden at build time:
//
//	go build -ldflags "-X .../internal/fingerprint.pepper=<random>"
//
// It MUST stay identical across releases: changing it changes every component,
// and every existing licence would stop matching its own machine. Rotate it only
// together with a server-side rebind of every live licence.
// pepperDefault is supplied by pepper_default.go (development) or by the
// generated pepper_gen.go under the `pepperbuild` tag (release). The release
// path writes a string *literal* instead of stamping the value with `-X`:
// `-X` puts the raw bytes in the symbol table where `strings h9b | grep` finds
// them in one command and garble cannot help, while a literal goes through
// garble's literal obfuscation and is stored encrypted.
var pepper = pepperBuild

// Component names are part of the wire format and of the stored licence. Rename
// one and every bound licence silently loses that component.
const (
	Machine = "machine" // Windows MachineGuid / /etc/machine-id / IOPlatformUUID
	MAC     = "mac"     // hash of the sorted set of physical NIC addresses
	Disk    = "disk"    // serial of the system disk
)

// Quorum is how many components must match for a stored licence to accept a
// machine. Two of three: one hardware change is tolerated, a cloned OS image is
// not.
const Quorum = 2

func hash(name, raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(pepper + "|" + name + "|" + raw))
	return hex.EncodeToString(sum[:])[:32]
}

// Components returns the per-component hashes present on this machine. A
// component the platform could not read is absent from the map rather than
// present-and-empty, so the server can tell "no disk serial available" from
// "different disk".
func Components() map[string]string {
	out := map[string]string{}
	if v := machineID(); v != "" {
		out[Machine] = hash(Machine, v)
	}
	if v := macSet(); v != "" {
		out[MAC] = hash(MAC, v)
	}
	if v := diskSerial(); v != "" {
		out[Disk] = hash(Disk, v)
	}
	return out
}

// Get returns the composite fingerprint sent to the server on every request.
//
// The composite is what rate limiting and logging key on. Binding decisions use
// Verify instead, because the composite changes whenever any one component does.
func Get() string {
	c := Components()
	names := make([]string, 0, len(c))
	for n := range c {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString(n)
		sb.WriteString("=")
		sb.WriteString(c[n])
		sb.WriteString(";")
	}
	sum := sha256.Sum256([]byte(pepper + "|composite|" + sb.String()))
	return hex.EncodeToString(sum[:])[:32]
}

// Verify compares a stored component set against this machine.
//
// Returns how many components matched and whether that clears the quorum. A
// stored set that is empty means the licence was never bound, and the caller
// should bind instead of verify.
func Verify(stored, current map[string]string) (matched int, ok bool) {
	if len(stored) == 0 {
		return 0, false
	}
	for name, want := range stored {
		if want == "" {
			continue
		}
		if got, present := current[name]; present && got == want {
			matched++
		}
	}
	return matched, matched >= Quorum
}

// Missing lists the components the stored licence knows about that this machine
// could not read at all. Used by `h9b doctor` to explain a refusal.
func Missing(stored, current map[string]string) []string {
	var out []string
	for name := range stored {
		if _, ok := current[name]; !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- platform

func machineID() string {
	switch runtime.GOOS {
	case "windows":
		// MachineGuid is written by Windows setup and survives feature updates.
		if v := regQuery(`HKLM\SOFTWARE\Microsoft\Cryptography`, "MachineGuid"); v != "" {
			return "win:" + v
		}
		return ""
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
		return ""
	default:
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil {
				if s := strings.TrimSpace(string(b)); s != "" {
					return "linux:" + s
				}
			}
		}
		return ""
	}
}

func regQuery(key, value string) string {
	out, err := exec.Command("reg", "query", key, "/v", value).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, value) {
			f := strings.Fields(line)
			if len(f) >= 3 {
				return f[len(f)-1]
			}
		}
	}
	return ""
}

// virtualIface matches interface names that are not physical hardware. A
// container, bridge or tunnel address changes without the machine changing, so
// including it would cause false lockouts.
var virtualPrefixes = []string{
	"lo", "docker", "veth", "br-", "virbr", "vmnet", "tun", "tap", "wg",
	"zt", "tailscale", "utun", "ppp", "sit", "ip6tnl", "dummy", "bond",
}

func isVirtual(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// macSet hashes the sorted set of physical NIC addresses.
//
// Sorting makes the value independent of enumeration order, which the kernel
// does not guarantee across boots. A set (not a single NIC) means Wi-Fi coming up
// as eth0 on one boot and wlan0 on the next is the same machine.
func macSet() string {
	var macs []string
	switch runtime.GOOS {
	case "windows":
		// -Physical excludes Hyper-V, VPN and loopback adapters. Win8+.
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetAdapter -Physical | Select-Object -ExpandProperty MacAddress").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if m := normMAC(line); m != "" {
					macs = append(macs, m)
				}
			}
		}
		if len(macs) == 0 {
			// Fallback for PowerShell being unavailable or policy-blocked.
			if o2, err := exec.Command("getmac", "/fo", "csv", "/nh").Output(); err == nil {
				for _, line := range strings.Split(string(o2), "\n") {
					for _, f := range strings.Split(line, ",") {
						if m := normMAC(f); m != "" {
							macs = append(macs, m)
						}
					}
				}
			}
		}
	default:
		entries, err := os.ReadDir("/sys/class/net")
		if err != nil {
			return ""
		}
		for _, e := range entries {
			if isVirtual(e.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join("/sys/class/net", e.Name(), "address"))
			if err != nil {
				continue
			}
			if m := normMAC(string(b)); m != "" {
				macs = append(macs, m)
			}
		}
	}
	if len(macs) == 0 {
		return ""
	}
	sort.Strings(macs)
	return strings.Join(macs, ",")
}

func normMAC(s string) string {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "\"'\r\n "))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 12 {
		return ""
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	// All-zero and all-ff are placeholders, not hardware.
	if s == "000000000000" || s == "ffffffffffff" {
		return ""
	}
	return s
}

// diskSerial returns the serial of the disk holding the OS.
//
// Windows: the system disk is whichever one carries C:. Linux: the block device
// backing /. Both are read best-effort; a machine without a readable serial just
// runs on the other two components.
func diskSerial() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-CimInstance Win32_DiskDrive | Where-Object { $_.Index -eq 0 } | Select-Object -First 1 -ExpandProperty SerialNumber)").Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	default:
		// Resolve / to its backing *physical* disk, then read the serial from
		// sysfs. The naive path (basename of the mount source) breaks on LVM,
		// LUKS and mdraid: / is /dev/mapper/ubuntu--vg-ubuntu--lv, which has no
		// /sys/block entry, so the component silently vanished and the box ran
		// on two components instead of three.
		out, err := exec.Command("findmnt", "-no", "SOURCE", "/").Output()
		if err != nil {
			return ""
		}
		dev := strings.TrimSpace(string(out))
		if dev == "" {
			return ""
		}
		base := physicalDisk(dev)
		if base == "" {
			return ""
		}
		for _, p := range []string{
			filepath.Join("/sys/block", base, "device", "serial"),
			filepath.Join("/sys/block", base, "serial"),
			filepath.Join("/sys/block", base, "device", "wwid"),
			filepath.Join("/sys/block", base, "wwid"),
		} {
			if b, err := os.ReadFile(p); err == nil {
				if s := strings.TrimSpace(string(b)); s != "" {
					return s
				}
			}
		}
		// Last resort: the disk's model and size. Weak, but stable for the same
		// box and better than dropping the component entirely.
		model, _ := os.ReadFile(filepath.Join("/sys/block", base, "device", "model"))
		size, _ := os.ReadFile(filepath.Join("/sys/block", base, "size"))
		m := strings.TrimSpace(string(model))
		if m == "" {
			return ""
		}
		return m + ":" + strings.TrimSpace(string(size))
	}
}

// physicalDisk walks the device stack (LVM, LUKS, mdraid, partitions) down to
// the physical disk that actually holds the data, and returns its kernel name
// (sda, nvme0n1, mmcblk0).
func physicalDisk(dev string) string {
	// lsblk -s prints the device followed by its parents, deepest last. -r is
	// required: without raw output lsblk prefixes tree glyphs ("└─sda") and the
	// name never matches a /sys/block entry.
	if out, err := exec.Command("lsblk", "-snro", "NAME,TYPE", dev).Output(); err == nil {
		var disk string
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[1] == "disk" {
				disk = f[0]
			}
		}
		if disk != "" {
			return disk
		}
	}
	// Fallback: walk /sys/block/*/slaves until nothing is left.
	base := filepath.Base(dev)
	for i := 0; i < 8; i++ {
		slaves, err := os.ReadDir(filepath.Join("/sys/class/block", base, "slaves"))
		if err != nil || len(slaves) == 0 {
			break
		}
		base = slaves[0].Name()
	}
	// base may still be a partition (sda3) — strip the trailing number.
	if strings.HasPrefix(base, "nvme") || strings.HasPrefix(base, "mmcblk") {
		if i := strings.LastIndex(base, "p"); i > 0 {
			base = base[:i]
		}
	} else if len(base) > 1 {
		base = strings.TrimRight(base, "0123456789")
	}
	if _, err := os.Stat(filepath.Join("/sys/block", base)); err != nil {
		return ""
	}
	return base
}

// SetPepper lets a build override the compiled-in pepper.
func SetPepper(p string) {
	if p != "" {
		pepper = p
	}
}
