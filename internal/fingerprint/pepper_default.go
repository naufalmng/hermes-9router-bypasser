//go:build !pepperbuild

package fingerprint

// pepperBuild is the development pepper. Release builds replace it with a
// generated pepper_gen.go compiled under the `pepperbuild` tag — see Makefile.
//
// A pepper is not a cryptographic boundary: the client must hash with something,
// so anyone who owns the binary can recover it. Its job is narrower and still
// worth doing — a leaked store.json is a list of hashes, and without a pepper
// those hashes are a 2^48 brute force away from customer MAC addresses.
const pepperBuild = "h9b-dev-pepper"
