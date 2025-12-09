package fingerprint

import "testing"

func TestIsValid(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		want        bool
	}{
		{
			name:        "valid SHA-256",
			fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
			want:        true,
		},
		{
			name:        "valid SHA-1",
			fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
			want:        true,
		},
		{
			name:        "lowercase - invalid",
			fingerprint: "aa:bb:cc:dd",
			want:        false,
		},
		{
			name:        "no colons - invalid",
			fingerprint: "AABBCCDD",
			want:        false,
		},
		{
			name:        "single character parts - invalid",
			fingerprint: "A:B:C:D",
			want:        false,
		},
		{
			name:        "three character parts - invalid",
			fingerprint: "AAA:BBB:CCC",
			want:        false,
		},
		{
			name:        "mixed case - invalid",
			fingerprint: "Aa:Bb:Cc:Dd",
			want:        false,
		},
		{
			name:        "non-hex characters - invalid",
			fingerprint: "GG:HH:II:JJ",
			want:        false,
		},
		{
			name:        "special characters - invalid",
			fingerprint: "AA-BB-CC-DD",
			want:        false,
		},
		{
			name:        "empty string - invalid",
			fingerprint: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValid(tt.fingerprint)
			if got != tt.want {
				t.Errorf("IsValid(%q) = %v, want %v", tt.fingerprint, got, tt.want)
			}
		})
	}
}
