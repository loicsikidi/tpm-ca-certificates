package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTPMRootsConfig_CheckAndSetDefault(t *testing.T) {
	tests := []struct {
		name    string
		config  TPMRootsConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						ID:   "TV",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URL:  "https://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{
										SHA1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing version",
			config: TPMRootsConfig{
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URL:  "https://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no vendors",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{},
			},
			wantErr: true,
		},
		{
			name: "vendor without name",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URL:  "https://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate without name",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								URL: "https://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate without url and uri",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid certificate with URI (https)",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URI:  "https://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid certificate with URI (file)",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URI:  "file:///{repo}/certs/root.pem",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid certificate with both URL and URI",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URL:  "https://example.com/cert.cer",
								URI:  "file:///{repo}/certs/root.pem",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "certificate with invalid URI scheme",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URI:  "ftp://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{SHA1: "AA:BB:CC"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate without fingerprint",
			config: TPMRootsConfig{
				Version: "alpha",
				Vendors: []Vendor{
					{
						Name: "Test Vendor",
						Certificates: []Certificate{
							{
								Name: "Test Cert",
								URL:  "https://example.com/cert.cer",
								Validation: Validation{
									Fingerprint: Fingerprint{},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.CheckAndSetDefault()
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAndSetDefault() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("valid config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, ".tpm-roots.yaml")

		validYAML := `version: alpha
vendors:
- id: "TV"
  name: "Test Vendor"
  certificates:
    - name: "Test Cert"
      url: "https://example.com/cert.cer"
      validation:
        fingerprint:
          sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`

		if err := os.WriteFile(configPath, []byte(validYAML), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if cfg.Version != "alpha" {
			t.Errorf("Version = %v, want %v", cfg.Version, "alpha")
		}

		if len(cfg.Vendors) != 1 {
			t.Fatalf("len(Vendors) = %v, want 1", len(cfg.Vendors))
		}

		if cfg.Vendors[0].Name != "Test Vendor" {
			t.Errorf("Vendor name = %v, want %v", cfg.Vendors[0].Name, "Test Vendor")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := LoadConfig("/non/existent/path.yaml")
		if err == nil {
			t.Error("LoadConfig() expected error for non-existent file")
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")

		if err := os.WriteFile(configPath, []byte("invalid: [yaml"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := LoadConfig(configPath)
		if err == nil {
			t.Error("LoadConfig() expected error for invalid YAML")
		}
	})
}

func TestCertificate_GetSourceLocation(t *testing.T) {
	tests := []struct {
		name string
		cert Certificate
		want string
	}{
		{
			name: "returns URI when present",
			cert: Certificate{
				URL: "https://example.com/old.cer",
				URI: "file://./certs/new.pem",
			},
			want: "file://./certs/new.pem",
		},
		{
			name: "returns URL when URI is empty",
			cert: Certificate{
				URL: "https://example.com/cert.cer",
			},
			want: "https://example.com/cert.cer",
		},
		{
			name: "returns empty when both are empty",
			cert: Certificate{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.GetSourceLocation()
			if got != tt.want {
				t.Errorf("GetSourceLocation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificate_Equal(t *testing.T) {
	tests := []struct {
		name  string
		cert1 *Certificate
		cert2 *Certificate
		want  bool
	}{
		{
			name: "equal by name",
			cert1: &Certificate{
				Name: "Same Name",
				URL:  "https://example.com/cert1.cer",
			},
			cert2: &Certificate{
				Name: "Same Name",
				URL:  "https://example.com/cert2.cer",
			},
			want: true,
		},
		{
			name: "equal by URL",
			cert1: &Certificate{
				Name: "Cert 1",
				URL:  "https://example.com/cert.cer",
			},
			cert2: &Certificate{
				Name: "Cert 2",
				URL:  "https://example.com/cert.cer",
			},
			want: true,
		},
		{
			name: "equal by URI",
			cert1: &Certificate{
				Name: "Cert 1",
				URI:  "file://./certs/root.pem",
			},
			cert2: &Certificate{
				Name: "Cert 2",
				URI:  "file://./certs/root.pem",
			},
			want: true,
		},
		{
			name: "equal when URL matches URI",
			cert1: &Certificate{
				Name: "Cert 1",
				URL:  "https://example.com/cert.cer",
			},
			cert2: &Certificate{
				Name: "Cert 2",
				URI:  "https://example.com/cert.cer",
			},
			want: true,
		},
		{
			name: "equal by fingerprint",
			cert1: &Certificate{
				Name: "Cert 1",
				URL:  "https://example.com/cert1.cer",
				Validation: Validation{
					Fingerprint: Fingerprint{SHA256: "ABC123"},
				},
			},
			cert2: &Certificate{
				Name: "Cert 2",
				URL:  "https://example.com/cert2.cer",
				Validation: Validation{
					Fingerprint: Fingerprint{SHA256: "ABC123"},
				},
			},
			want: true,
		},
		{
			name: "not equal",
			cert1: &Certificate{
				Name: "Cert 1",
				URL:  "https://example.com/cert1.cer",
				Validation: Validation{
					Fingerprint: Fingerprint{SHA256: "ABC123"},
				},
			},
			cert2: &Certificate{
				Name: "Cert 2",
				URL:  "https://example.com/cert2.cer",
				Validation: Validation{
					Fingerprint: Fingerprint{SHA256: "DEF456"},
				},
			},
			want: false,
		},
		{
			name:  "nil certificates",
			cert1: nil,
			cert2: &Certificate{Name: "Cert"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert1.Equal(tt.cert2)
			if got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
