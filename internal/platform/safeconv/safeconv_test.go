package safeconv

import (
	"math"
	"testing"
)

func TestInt32Clamps(t *testing.T) {
	cases := []struct {
		in   int
		want int32
	}{
		{0, 0},
		{42, 42},
		{-42, -42},
		{math.MaxInt32, math.MaxInt32},
		{math.MinInt32, math.MinInt32},
	}
	for _, tc := range cases {
		if got := Int32(tc.in); got != tc.want {
			t.Errorf("Int32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	// On a 64-bit platform these exceed int32 and would wrap under a plain
	// conversion, producing a negative number from a positive input.
	if got := Int32(math.MaxInt32 + 1); got != math.MaxInt32 {
		t.Errorf("Int32(MaxInt32+1) = %d, want saturation at MaxInt32", got)
	}
	if got := Int32(math.MinInt32 - 1); got != math.MinInt32 {
		t.Errorf("Int32(MinInt32-1) = %d, want saturation at MinInt32", got)
	}
}

func TestNonNegativeInt32(t *testing.T) {
	if got := NonNegativeInt32(-1); got != 0 {
		t.Errorf("NonNegativeInt32(-1) = %d, want 0", got)
	}
	if got := NonNegativeInt32(7); got != 7 {
		t.Errorf("NonNegativeInt32(7) = %d, want 7", got)
	}
}

func TestInt32From64(t *testing.T) {
	if got := Int32From64(math.MaxInt64); got != math.MaxInt32 {
		t.Errorf("Int32From64(MaxInt64) = %d, want MaxInt32", got)
	}
	if got := Int32From64(5); got != 5 {
		t.Errorf("Int32From64(5) = %d, want 5", got)
	}
}

func TestDigit(t *testing.T) {
	for i := int64(0); i <= 9; i++ {
		if got := Digit(i); got != byte('0'+i) {
			t.Errorf("Digit(%d) = %q, want %q", i, got, byte('0'+i))
		}
	}
	// Out-of-range input must still yield a decimal digit, never an arbitrary
	// byte inside a one-time password.
	for _, bad := range []int64{-1, 10, 99} {
		got := Digit(bad)
		if got < '0' || got > '9' {
			t.Errorf("Digit(%d) = %q, which is not a decimal digit", bad, got)
		}
	}
}
