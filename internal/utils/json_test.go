package utils

import (
	"testing"
)

func TestJsonCompact(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "compact JSON with whitespace",
			input:   []byte(`{"foo": "bar", "baz": 123}`),
			want:    []byte(`{"foo":"bar","baz":123}`),
			wantErr: false,
		},
		{
			name:    "already compact JSON",
			input:   []byte(`{"foo":"bar","baz":123}`),
			want:    []byte(`{"foo":"bar","baz":123}`),
			wantErr: false,
		},
		{
			name:    "JSON with newlines and tabs",
			input:   []byte("{\n\t\"foo\": \"bar\",\n\t\"baz\": 123\n}"),
			want:    []byte(`{"foo":"bar","baz":123}`),
			wantErr: false,
		},
		{
			name:    "nested JSON with whitespace",
			input:   []byte(`{"outer": {"inner": "value"}, "array": [1, 2, 3]}`),
			want:    []byte(`{"outer":{"inner":"value"},"array":[1,2,3]}`),
			wantErr: false,
		},
		{
			name:    "empty JSON object",
			input:   []byte(`{}`),
			want:    []byte(`{}`),
			wantErr: false,
		},
		{
			name:    "empty JSON array",
			input:   []byte(`[]`),
			want:    []byte(`[]`),
			wantErr: false,
		},
		{
			name:    "invalid JSON - missing closing brace",
			input:   []byte(`{"foo": "bar"`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid JSON - trailing comma",
			input:   []byte(`{"foo": "bar",}`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid JSON - malformed",
			input:   []byte(`not json at all`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte(``),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JsonCompact(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("JsonCompact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("JsonCompact() = %s, want %s", got, tt.want)
			}
		})
	}
}
