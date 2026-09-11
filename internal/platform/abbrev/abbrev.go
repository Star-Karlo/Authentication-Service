// Package abbrev derives a company's short code from its name.
//
// The code appears in agreement numbers — AGR-JYA-ASB-000001 — where its whole
// job is to be recognisable when someone reads it back over the phone. That is
// why it is derived rather than random, and why it is not required to be
// unique: a clash costs legibility, while refusing a registration over one
// costs a customer.
package abbrev

import (
	"regexp"
	"strings"
	"unicode"
)

// legalForms are the words that begin or end nearly every Indonesian company
// name. Left in, "PT Sumber Makmur" and "PT Sinar Jaya" would both abbreviate
// to PTS — the opposite of what a distinguishing code is for.
var legalForms = map[string]bool{
	"pt": true, "cv": true, "ud": true, "pd": true, "tbk": true,
	"persero": true, "perseroan": true,
}

var nonAlphanumeric = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)

// MaxLength is what the agreement number format has room for.
const MaxLength = 3

// FromName derives a code of at most three characters.
//
// Multi-word names give the initial of each word; a single word gives its first
// three letters. The split matters: "MAST" would otherwise become "M", which
// nobody can read back, while "PT Lintas Jaya Logistik" becoming LJL is exactly
// right.
//
// Returns "CO" for a name with nothing usable in it — an empty code would
// produce AGR--ASB-000001, which is worse than a generic one.
func FromName(name string) string {
	cleaned := nonAlphanumeric.ReplaceAllString(name, " ")

	words := make([]string, 0, 4)
	for _, word := range strings.Fields(cleaned) {
		if legalForms[strings.ToLower(word)] {
			continue
		}
		words = append(words, word)
	}

	if len(words) == 0 {
		// The name was nothing but a legal form: "PT" alone, or punctuation.
		// Fall back to the raw name rather than to nothing.
		words = strings.Fields(cleaned)
	}
	if len(words) == 0 {
		return "CO"
	}

	var code string
	if len(words) == 1 {
		code = words[0]
	} else {
		var initials strings.Builder
		for _, word := range words {
			initials.WriteString(word[:1])
		}
		code = initials.String()
	}

	return clamp(code)
}

// Normalise cleans a code somebody typed, so a stored one always has the shape
// the number format expects.
func Normalise(code string) string {
	return clamp(code)
}

func clamp(code string) string {
	code = strings.ToUpper(keepAlphanumeric(code))
	if len(code) > MaxLength {
		code = code[:MaxLength]
	}
	if code == "" {
		return "CO"
	}
	return code
}

func keepAlphanumeric(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
