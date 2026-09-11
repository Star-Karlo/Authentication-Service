package abbrev

import "testing"

func TestFromName(t *testing.T) {
	cases := map[string]string{
		// Multi-word: initials, with the legal form dropped. Without that drop
		// every PT company would start with P and the code would distinguish
		// nothing.
		"PT Lintas Jaya Logistik":     "LJL",
		"PT. Sumber Makmur Sejahtera": "SMS",
		"CV Sinar Jaya":               "SJ",
		"PT Jaya Abadi":               "JA",
		"Agribisnis Sukses Bersama":   "ASB",

		// Single word: the first three letters, because one initial is not a
		// code anybody can read back.
		"MAST":  "MAS",
		"Karlo": "KAR",

		// Longer than three initials is truncated to what the number has room
		// for.
		"PT Sumber Makmur Sejahtera Abadi Jaya": "SMS",

		// Nothing usable.
		"PT":  "PT",
		"":    "CO",
		"...": "CO",
	}

	for name, want := range cases {
		if got := FromName(name); got != want {
			t.Errorf("FromName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNormalise(t *testing.T) {
	cases := map[string]string{
		"ski":     "SKI",
		"s k i":   "SKI",
		"s-k-i":   "SKI",
		"TOOLONG": "TOO",
		"":        "CO",
	}
	for in, want := range cases {
		if got := Normalise(in); got != want {
			t.Errorf("Normalise(%q) = %q, want %q", in, got, want)
		}
	}
}
