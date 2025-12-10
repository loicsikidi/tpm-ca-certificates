package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v4"
)

const (
	SHA1   = "sha1"
	SHA256 = "sha256"
	SHA384 = "sha384"
	SHA512 = "sha512"
)

// TPMRootsConfig represents the root configuration from .tpm-roots.yaml file.
type TPMRootsConfig struct {
	Version string   `yaml:"version"`
	Vendors []Vendor `yaml:"vendors"`
}

// CheckAndSetDefault validates the TPMRootsConfig structure.
func (c *TPMRootsConfig) CheckAndSetDefault() error {
	if c.Version == "" {
		return errors.New("invalid input: 'version' cannot be empty")
	}

	if len(c.Vendors) == 0 {
		return errors.New("invalid input: at least one vendor must be defined")
	}

	for i, vendor := range c.Vendors {
		if err := vendor.CheckAndSetDefault(); err != nil {
			var errMsg string
			if vendor.Name == "" {
				errMsg = fmt.Sprintf("vendor[%d]", i)
			} else {
				errMsg = fmt.Sprintf("vendor.name: %s", vendor.Name)
			}
			return fmt.Errorf("%s: %w", errMsg, err)
		}
	}

	return nil
}

// TotalCertificates returns the total number of certificates defined across all vendors.
func (c *TPMRootsConfig) TotalCertificates() int {
	total := 0
	for _, vendor := range c.Vendors {
		total += len(vendor.Certificates)
	}
	return total
}

// Vendor represents a TPM vendor with their certificates.
type Vendor struct {
	ID           string        `yaml:"id"`
	Name         string        `yaml:"name"`
	Certificates []Certificate `yaml:"certificates"`
}

// CheckAndSetDefault validates a Vendor.
func (v *Vendor) CheckAndSetDefault() error {
	if v.Name == "" {
		return errors.New("invalid input: 'name' cannot be empty")
	}

	for i, cert := range v.Certificates {
		if err := cert.CheckAndSetDefault(); err != nil {
			var errMsg string
			if cert.Name == "" {
				errMsg = fmt.Sprintf("certificate[%d]", i)
			} else {
				errMsg = fmt.Sprintf("certificate.name: %s", cert.Name)
			}
			return fmt.Errorf("%s: %w", errMsg, err)
		}
	}

	return nil
}

// Certificate represents a single certificate with its download URL and validation rules.
type Certificate struct {
	Name       string     `yaml:"name"`
	URL        string     `yaml:"url"`
	Validation Validation `yaml:"validation"`
}

// CheckAndSetDefault validates a Certificate.
func (c *Certificate) CheckAndSetDefault() error {
	if c.Name == "" {
		return errors.New("invalid input: 'name' cannot be empty")
	}

	if c.URL == "" {
		return errors.New("invalid input: 'url' cannot be empty")
	}

	if err := c.Validation.Fingerprint.CheckAndSetDefault(); err != nil {
		return fmt.Errorf("validation: %w", err)
	}

	return nil
}

// Equal checks if two certificates are considered equal based on Name, URL, or Fingerprint.
func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return false
	}

	fp, _ := c.Validation.Fingerprint.GetFingerprintValue()
	otherFP, _ := other.Validation.Fingerprint.GetFingerprintValue()

	return c.Name == other.Name || c.URL == other.URL ||
		fp == otherFP
}

// Validation contains fingerprint validation rules for a certificate.
type Validation struct {
	Fingerprint Fingerprint `yaml:"fingerprint"`
}

// Fingerprint contains hash-based fingerprints for certificate validation.
//
// Supported algorithms: sha1, sha256, sha384, sha512.
type Fingerprint struct {
	SHA1   string `yaml:"sha1,omitempty"`
	SHA256 string `yaml:"sha256,omitempty"`
	SHA384 string `yaml:"sha384,omitempty"`
	SHA512 string `yaml:"sha512,omitempty"`
}

// CheckAndSetDefault validates a Fingerprint.
func (f *Fingerprint) CheckAndSetDefault() error {
	if f.SHA1 == "" && f.SHA256 == "" && f.SHA384 == "" && f.SHA512 == "" {
		return errors.New("invalid input: at least one fingerprint (sha1, sha256, sha384, sha512) must be provided")
	}

	return nil
}

// NewFingerprint creates a with given hash algorithm and value.
func NewFingerprint(hashAlgo string, value string) *Fingerprint {
	fp := &Fingerprint{}
	switch strings.ToLower(hashAlgo) {
	case SHA1:
		fp.SHA1 = value
	case SHA256:
		fp.SHA256 = value
	case SHA384:
		fp.SHA384 = value
	case SHA512:
		fp.SHA512 = value
	}
	return fp
}

// GetFingerprintValue returns the most secure fingerprint value and its corresponding hash algorithm.
//
// Priority order (most to least secure): SHA512, SHA384, SHA256, SHA1.
func (f *Fingerprint) GetFingerprintValue() (fingerprint string, hashAlg string) {
	if f.SHA512 != "" {
		return f.SHA512, SHA512
	}
	if f.SHA384 != "" {
		return f.SHA384, SHA384
	}
	if f.SHA256 != "" {
		return f.SHA256, SHA256
	}
	return f.SHA1, SHA1
}

// LoadConfig reads and parses the TPM roots configuration from a YAML file.
//
// Example:
//
//	cfg, err := config.LoadConfig(".tpm-roots.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadConfig(path string) (*TPMRootsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg TPMRootsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// SaveConfig writes the TPM roots configuration to a YAML file.
//
// Example:
//
//	err := config.SaveConfig(".tpm-roots.yaml", cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
func SaveConfig(path string, cfg *TPMRootsConfig) error {
	if err := cfg.CheckAndSetDefault(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
