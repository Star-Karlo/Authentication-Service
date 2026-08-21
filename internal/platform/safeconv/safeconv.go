// Package safeconv holds bounded numeric conversions.
//
// Go's integer conversions wrap silently: int32(math.MaxInt32 + 1) is negative,
// not an error. Most of the conversions in this codebase go from an int that a
// database or a configuration file supplied into the int32 a protobuf field
// declares, so a bad value is possible even if unlikely — and a negative
// geofence radius or page count is worse than a clamped one.
//
// These helpers clamp rather than error. At every call site the value is being
// rendered for display or transport, where a saturated value is correct enough
// and an error would fail a whole response over one field.
package safeconv

import "math"

// Int32 converts an int, clamping to the int32 range.
func Int32(v int) int32 {
	switch {
	case v > math.MaxInt32:
		return math.MaxInt32
	case v < math.MinInt32:
		return math.MinInt32
	default:
		return int32(v)
	}
}

// Int32From64 converts an int64, clamping to the int32 range.
func Int32From64(v int64) int32 {
	switch {
	case v > math.MaxInt32:
		return math.MaxInt32
	case v < math.MinInt32:
		return math.MinInt32
	default:
		return int32(v)
	}
}

// NonNegativeInt32 converts an int, clamping to [0, MaxInt32].
//
// Used for counts and durations, where a negative value is never meaningful and
// would be read by a client as an enormous unsigned number.
func NonNegativeInt32(v int) int32 {
	if v < 0 {
		return 0
	}
	return Int32(v)
}

// Digit converts a single decimal digit to its ASCII byte.
//
// The input is expected to be in [0, 9]; anything else is clamped, so a
// generator fault produces a wrong digit rather than an arbitrary byte in the
// middle of a one-time password.
func Digit(v int64) byte {
	if v < 0 {
		v = 0
	}
	if v > 9 {
		v = 9
	}
	return byte('0' + v)
}
