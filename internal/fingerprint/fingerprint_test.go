package fingerprint

import (
	"testing"
)

// A licence store that leaks must not be reversible into a customer's MAC
// address, and the composite must not be forgeable by swapping one component.
func TestVerifyQuorum(t *testing.T) {
	box := map[string]string{
		Machine: hash(Machine, "linux:aaa"),
		MAC:     hash(MAC, "001122334455"),
		Disk:    hash(Disk, "SN123"),
	}

	cases := []struct {
		name    string
		stored  map[string]string
		current map[string]string
		want    int
		ok      bool
	}{
		{
			name:    "same machine",
			stored:  box,
			current: box,
			want:    3,
			ok:      true,
		},
		{
			name:   "nic swapped, machine and disk agree",
			stored: box,
			current: map[string]string{
				Machine: box[Machine],
				MAC:     hash(MAC, "aabbccddeeff"),
				Disk:    box[Disk],
			},
			want: 2,
			ok:   true,
		},
		{
			name:   "disk replaced, machine and mac agree",
			stored: box,
			current: map[string]string{
				Machine: box[Machine],
				MAC:     box[MAC],
				Disk:    hash(Disk, "SN999"),
			},
			want: 2,
			ok:   true,
		},
		{
			// The attack the MAC lock exists to stop: someone copies
			// /etc/machine-id (or clones a VM image) onto different hardware.
			name:   "cloned machine-id on different hardware",
			stored: box,
			current: map[string]string{
				Machine: box[Machine],
				MAC:     hash(MAC, "deadbeef0001"),
				Disk:    hash(Disk, "OTHER"),
			},
			want: 1,
			ok:   false,
		},
		{
			name:   "different machine entirely",
			stored: box,
			current: map[string]string{
				Machine: hash(Machine, "linux:bbb"),
				MAC:     hash(MAC, "999999999999"),
				Disk:    hash(Disk, "SN000"),
			},
			want: 0,
			ok:   false,
		},
		{
			// A kernel update made the disk serial unreadable. Two components
			// still match, so the customer keeps working instead of filing a
			// ticket on a Sunday.
			name:   "disk serial unreadable now",
			stored: box,
			current: map[string]string{
				Machine: box[Machine],
				MAC:     box[MAC],
			},
			want: 2,
			ok:   true,
		},
		{
			name:    "never bound",
			stored:  nil,
			current: box,
			want:    0,
			ok:      false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Verify(c.stored, c.current)
			if got != c.want || ok != c.ok {
				t.Fatalf("Verify() = (%d, %v), want (%d, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}

// The composite must change when any component changes, otherwise the server's
// rate limiter and audit log cannot tell two boxes apart.
func TestComponentsAreIndependent(t *testing.T) {
	a := hash(Machine, "same")
	b := hash(MAC, "same")
	if a == b {
		t.Fatal("same raw value under different component names must not collide")
	}
	if hash(MAC, "001122334455") == hash(MAC, "001122334456") {
		t.Fatal("different MACs must hash differently")
	}
}

// normMAC is the gate between "a string that looks like an address" and a value
// that can silently bind a licence. Anything that is not 12 hex digits, and any
// placeholder, must be rejected rather than hashed.
func TestNormMAC(t *testing.T) {
	good := map[string]string{
		"00:11:22:33:44:55":     "001122334455",
		"00-11-22-33-44-55":     "001122334455",
		"  AA:BB:CC:DD:EE:FF\n": "aabbccddeeff",
		`"001122334455"`:        "001122334455",
	}
	for in, want := range good {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"", "00:11:22:33:44", "00:11:22:33:44:55:66",
		"zz:11:22:33:44:55", "000000000000", "FF-FF-FF-FF-FF-FF",
		"Internet", "-",
	} {
		if got := normMAC(bad); got != "" {
			t.Errorf("normMAC(%q) = %q, want empty", bad, got)
		}
	}
}

func TestVirtualInterfacesExcluded(t *testing.T) {
	virtual := []string{
		"lo", "docker0", "veth1a2b3c", "br-9f8e", "virbr0", "tun0", "tap0",
		"wg0", "tailscale0", "utun3", "ppp0",
	}
	physical := []string{"eth0", "enp3s0", "wlan0", "wlp2s0", "eno1"}
	for _, n := range virtual {
		if !isVirtual(n) {
			t.Errorf("%q should be treated as virtual", n)
		}
	}
	for _, n := range physical {
		if isVirtual(n) {
			t.Errorf("%q should be treated as physical", n)
		}
	}
}

// Get must be stable across calls: the client sends it on every request and the
// server rate-limits on it.
func TestGetStable(t *testing.T) {
	a, b := Get(), Get()
	if a != b {
		t.Fatalf("Get() not stable: %s vs %s", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("Get() length = %d, want 32", len(a))
	}
}
