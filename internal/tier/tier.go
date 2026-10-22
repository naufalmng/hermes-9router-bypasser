// Package tier maps a licence to the products it is allowed to patch.
//
// The customer sells three things, and the difference has to be enforced on the
// server, not hinted at in the client: a Basic licence must never receive the
// other product's recipes, because whatever the client receives can be dumped
// from its memory. Filtering here means a Basic customer who reverses the binary
// still finds only the recipes they paid for.
package tier

import (
	"fmt"
	"strings"
)

const (
	// Hermes is Basic: the Hermes guardrail recipes only.
	Hermes = "hermes"
	// Router9 is Basic: the 9router recipes only.
	Router9 = "router9"
	// Pro is both.
	Pro = "pro"
)

// Products maps a recipe id to the product it belongs to.
//
// Recipes are namespaced by prefix (`hg-` / `r9-`) rather than carrying a field,
// so a payload authored before this package existed still filters correctly.
// An empty return means "core" — a recipe that applies to every tier.
func Product(recipeID string) string {
	switch {
	case strings.HasPrefix(recipeID, "hg-"):
		return Hermes
	case strings.HasPrefix(recipeID, "r9-"):
		return Router9
	}
	return ""
}

// Allows reports whether a licence tier may receive a recipe.
//
// Unknown tiers are denied for product recipes (fail closed): a typo in
// `cdk new -tier` must not hand out Pro.
func Allows(t, recipeID string) bool {
	p := Product(recipeID)
	if p == "" {
		return true
	}
	switch t {
	case Pro:
		return true
	case Hermes, Router9:
		return p == t
	}
	return false
}

// Normalize accepts the spellings an operator is likely to type and returns the
// canonical tier, or an error naming the choices.
func Normalize(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	v = strings.ReplaceAll(v, "_", "-")
	v = strings.ReplaceAll(v, " ", "-")
	switch v {
	case "hermes", "basic-hermes", "h":
		return Hermes, nil
	case "router9", "9router", "basic-router9", "basic-9router", "r9", "r":
		return Router9, nil
	case "pro", "both", "all", "full":
		return Pro, nil
	case "basic", "b":
		// Basic splits into two products, so the bare word is ambiguous and
		// guessing would silently sell the wrong half.
		return "", fmt.Errorf("tier %q is ambiguous: use basic-hermes or basic-router9", s)
	}
	return "", fmt.Errorf("unknown tier %q (use: basic-hermes | basic-router9 | pro)", s)
}

// Label is the human name shown in the CLI and in `lic list`.
func Label(t string) string {
	switch t {
	case Hermes:
		return "Basic (Hermes)"
	case Router9:
		return "Basic (9router)"
	case Pro:
		return "Pro (Hermes+9router)"
	}
	return t
}
