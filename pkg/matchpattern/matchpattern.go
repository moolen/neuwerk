// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"errors"
	"regexp"
	"strings"
)

const allowedDNSCharsREGroup = "[-a-zA-Z0-9_]"

// Validate ensures that pattern is a parseable matchPattern. It returns the
// regexp generated when validating.
func Validate(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(Sanitize(pattern)); err != nil {
		return nil, err
	}
	return regexp.Compile(ToRegexp(Sanitize(pattern)))
}

// ValidateWithoutCache is the same as Validate() but doesn't consult the regex
// LRU.
func ValidateWithoutCache(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(ToRegexp(pattern))
}

func prevalidate(pattern string) error {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// error check
	if strings.ContainsAny(pattern, "[]+{},") {
		return errors.New(`Only alphanumeric ASCII characters, the hyphen "-", underscore "_", "." and "*" are allowed in a matchPattern`)
	}

	return nil
}

// Sanitize canonicalized the pattern for use by ToRegexp
func Sanitize(pattern string) string {
	if pattern == "*" {
		return pattern
	}

	return FQDN(pattern)
}

// ToRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern.
// It supports:
// * to select 0 or more DNS valid characters
func ToRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle the * match-all case. This will filter down to the end.
	if pattern == "*" {
		return "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)"
	}

	// base case. * becomes .*, but only for DNS valid characters
	// NOTE: this only works because the case above does not leave the *
	pattern = strings.Replace(pattern, "*", allowedDNSCharsREGroup+"*", -1)

	// base case. "." becomes a literal .
	pattern = strings.Replace(pattern, ".", "[.]", -1)

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}

// isFQDN reports whether the domain name s is fully qualified.
func isFQDN(s string) bool {
	s2 := strings.TrimSuffix(s, ".")
	if s == s2 {
		return false
	}

	i := strings.LastIndexFunc(s2, func(r rune) bool {
		return r != '\\'
	})

	// Test whether we have an even number of escape sequences before
	// the dot or none.
	return (len(s2)-i)%2 != 0
}

// FQDN returns the fully qualified domain name from s.
// If s is already fully qualified, it behaves as the identity function.
func FQDN(s string) string {
	if isFQDN(s) {
		return strings.ToLower(s)
	}
	return strings.ToLower(s) + "."
}
