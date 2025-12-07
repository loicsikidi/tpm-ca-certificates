package digest

import (
	"testing"
)

func TestComputeSHA256(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantDigest string
	}{
		{
			name:       "empty content",
			content:    "",
			wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:       "simple content",
			content:    "hello world\n",
			wantDigest: "sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
		},
		{
			name:       "binary content",
			content:    "\x00\x01\x02\x03",
			wantDigest: "sha256:054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeSHA256([]byte(tt.content))

			if got != tt.wantDigest {
				t.Errorf("ComputeSHA256() = %q, want %q", got, tt.wantDigest)
			}
		})
	}
}
