package utils

import "errors"

var ErrArgNotProvided = errors.New("argument not provided")

func optionalArg[T any](arg []T) (T, error) {
	if len(arg) == 0 {
		var zero T
		return zero, ErrArgNotProvided
	}
	return arg[0], nil
}

// OptionalArg returns the first element of the provided slice,
// or the zero value of T if the slice is empty.
func OptionalArg[T any](arg []T) T {
	v, _ := optionalArg(arg)
	return v
}

// OptionalArgWithDefault returns the first element of the provided slice,
// or the provided defaultValue if the slice is empty.
func OptionalArgWithDefault[T any](arg []T, defaultValue T) T {
	v, err := optionalArg(arg)
	if err != nil {
		return defaultValue
	}
	return v
}
