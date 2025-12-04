package github

import "testing"

func TestIsDateTag(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want bool
	}{
		{
			name: "valid date tag",
			tag:  "2025-12-03",
			want: true,
		},
		{
			name: "valid date tag with zeros",
			tag:  "2025-01-01",
			want: true,
		},
		{
			name: "invalid - too short",
			tag:  "2025-1-1",
			want: false,
		},
		{
			name: "invalid - too long",
			tag:  "2025-12-031",
			want: false,
		},
		{
			name: "invalid - missing dashes",
			tag:  "20251203",
			want: false,
		},
		{
			name: "invalid - wrong separator",
			tag:  "2025/12/03",
			want: false,
		},
		{
			name: "invalid - contains letters",
			tag:  "2025-1a-03",
			want: false,
		},
		{
			name: "invalid - semantic version",
			tag:  "v1.2.3",
			want: false,
		},
		{
			name: "invalid - empty string",
			tag:  "",
			want: false,
		},
		{
			name: "invalid - spaces",
			tag:  "2025 12 03",
			want: false,
		},
		{
			name: "invalid - extra characters",
			tag:  "v2025-12-03",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDateTag(tt.tag)
			if got != tt.want {
				t.Errorf("isDateTag(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}
