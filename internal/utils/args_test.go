package utils_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

type TestCase[T any] struct {
	name string
	args []T
	want T
}

func TestOptionalArg(t *testing.T) {
	tint := []TestCase[int]{
		{
			name: "argument provided",
			args: []int{42},
			want: 42,
		},
		{
			name: "argument not provided",
			args: []int{},
			want: 0,
		},
	}
	tinterface := []TestCase[utils.HTTPClient]{
		{
			name: "argument provided",
			args: []utils.HTTPClient{http.DefaultClient},
			want: http.DefaultClient,
		},
		{
			name: "argument not provided",
			args: []utils.HTTPClient{},
			want: nil,
		},
	}
	tslice := []TestCase[[]int]{
		{
			name: "argument provided",
			args: [][]int{{1, 2, 3}, {4, 5, 6}},
			want: []int{1, 2, 3},
		},
		{
			name: "argument not provided",
			args: [][]int{},
			want: nil,
		},
	}

	testOptionalArg(t, tint)
	testOptionalArg(t, tinterface)
	testOptionalArgWithSlice(t, tslice)
}

func testOptionalArg[T comparable](t *testing.T, tests []TestCase[T]) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.OptionalArg(tt.args)
			if got != tt.want {
				t.Errorf("OptionalArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
func testOptionalArgWithSlice[S ~[]E, E comparable](t *testing.T, tests []TestCase[S]) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.OptionalArg(tt.args)
			if !slices.Equal(got, tt.want) {
				t.Errorf("OptionalArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
