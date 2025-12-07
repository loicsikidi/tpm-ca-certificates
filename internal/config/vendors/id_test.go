package vendors

import (
	"testing"
)

func TestID_Validate(t *testing.T) {
	tests := []struct {
		name    string
		id      ID
		wantErr bool
	}{
		{
			name:    "valid vendor ID - STM",
			id:      "STM",
			wantErr: false,
		},
		{
			name:    "valid vendor ID - IFX",
			id:      "IFX",
			wantErr: false,
		},
		{
			name:    "valid vendor ID - INTC",
			id:      "INTC",
			wantErr: false,
		},
		{
			name:    "invalid vendor ID - INVALID",
			id:      "INVALID",
			wantErr: true,
		},
		{
			name:    "invalid vendor ID - empty",
			id:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ID.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestID_String(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want string
	}{
		{
			name: "STM",
			id:   "STM",
			want: "STM",
		},
		{
			name: "empty",
			id:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.String(); got != tt.want {
				t.Errorf("ID.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
