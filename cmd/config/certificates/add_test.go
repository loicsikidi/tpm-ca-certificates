package certificates

import (
	"strings"
	"testing"
)

func TestValidateAndPrepareInputs(t *testing.T) {
	t.Run("rejects HTTP URL", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "http://example.com/cert.crt",
			HashAlgorithm: "sha256",
		}

		_, _, _, err := validateAndPrepareInputs(opts)
		if err == nil {
			t.Fatal("validateAndPrepareInputs() error = nil, want error for HTTP URL")
		}

		if !strings.Contains(err.Error(), "insecure HTTP URL not allowed") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'insecure HTTP URL not allowed'", err)
		}
	})

	t.Run("rejects multiple URLs with HTTP", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert1.crt,http://example.com/cert2.crt",
			HashAlgorithm: "sha256",
		}

		_, _, _, err := validateAndPrepareInputs(opts)
		if err == nil {
			t.Fatal("validateAndPrepareInputs() error = nil, want error for HTTP URL")
		}

		if !strings.Contains(err.Error(), "insecure HTTP URL not allowed") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'insecure HTTP URL not allowed'", err)
		}
	})

	t.Run("rejects invalid URL scheme", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "ftp://example.com/cert.crt",
			HashAlgorithm: "sha256",
		}

		_, _, _, err := validateAndPrepareInputs(opts)
		if err == nil {
			t.Fatal("validateAndPrepareInputs() error = nil, want error for invalid URL scheme")
		}

		if !strings.Contains(err.Error(), "invalid URL scheme") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'invalid URL scheme'", err)
		}
		if !strings.Contains(err.Error(), "must use HTTPS") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'must use HTTPS'", err)
		}
	})

	t.Run("accepts HTTPS URL", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert.crt",
			HashAlgorithm: "sha256",
		}

		hashAlgo, urls, fingerprints, err := validateAndPrepareInputs(opts)
		if err != nil {
			t.Fatalf("validateAndPrepareInputs() error = %v, want nil", err)
		}

		if hashAlgo != "sha256" {
			t.Errorf("validateAndPrepareInputs() hashAlgo = %s, want sha256", hashAlgo)
		}
		if len(urls) != 1 {
			t.Fatalf("validateAndPrepareInputs() urls length = %d, want 1", len(urls))
		}
		if urls[0] != "https://example.com/cert.crt" {
			t.Errorf("validateAndPrepareInputs() urls[0] = %s, want https://example.com/cert.crt", urls[0])
		}
		if len(fingerprints) != 0 {
			t.Errorf("validateAndPrepareInputs() fingerprints length = %d, want 0", len(fingerprints))
		}
	})

	t.Run("accepts multiple HTTPS URLs", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert1.crt,https://example.com/cert2.crt",
			HashAlgorithm: "sha256",
		}

		_, urls, _, err := validateAndPrepareInputs(opts)
		if err != nil {
			t.Fatalf("validateAndPrepareInputs() error = %v, want nil", err)
		}

		if len(urls) != 2 {
			t.Fatalf("validateAndPrepareInputs() urls length = %d, want 2", len(urls))
		}
		if urls[0] != "https://example.com/cert1.crt" {
			t.Errorf("validateAndPrepareInputs() urls[0] = %s, want https://example.com/cert1.crt", urls[0])
		}
		if urls[1] != "https://example.com/cert2.crt" {
			t.Errorf("validateAndPrepareInputs() urls[1] = %s, want https://example.com/cert2.crt", urls[1])
		}
	})

	t.Run("rejects invalid hash algorithm", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert.crt",
			HashAlgorithm: "md5",
		}

		_, _, _, err := validateAndPrepareInputs(opts)
		if err == nil {
			t.Fatal("validateAndPrepareInputs() error = nil, want error for invalid hash algorithm")
		}

		if !strings.Contains(err.Error(), "invalid hash algorithm") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'invalid hash algorithm'", err)
		}
	})

	t.Run("rejects fingerprint count mismatch", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert1.crt,https://example.com/cert2.crt",
			Fingerprint:   "SHA256:AB:CD:EF",
			HashAlgorithm: "sha256",
		}

		_, _, _, err := validateAndPrepareInputs(opts)
		if err == nil {
			t.Fatal("validateAndPrepareInputs() error = nil, want error for fingerprint count mismatch")
		}

		if !strings.Contains(err.Error(), "number of fingerprints") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'number of fingerprints'", err)
		}
	})

	t.Run("infers hash algorithm from SHA256 fingerprint", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert.crt",
			Fingerprint:   "SHA256:AB:CD:EF:01:23:45:67:89",
			HashAlgorithm: "sha256", // default value
		}

		hashAlgo, urls, fingerprints, err := validateAndPrepareInputs(opts)
		if err != nil {
			t.Fatalf("validateAndPrepareInputs() error = %v, want nil", err)
		}

		if hashAlgo != "sha256" {
			t.Errorf("validateAndPrepareInputs() hashAlgo = %s, want sha256", hashAlgo)
		}
		if len(urls) != 1 {
			t.Fatalf("validateAndPrepareInputs() urls length = %d, want 1", len(urls))
		}
		if len(fingerprints) != 1 {
			t.Fatalf("validateAndPrepareInputs() fingerprints length = %d, want 1", len(fingerprints))
		}
	})

	t.Run("infers hash algorithm from SHA512 fingerprint", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert.crt",
			Fingerprint:   "SHA512:AB:CD:EF:01:23:45:67:89",
			HashAlgorithm: "sha256", // default value, should be overridden
		}

		hashAlgo, urls, fingerprints, err := validateAndPrepareInputs(opts)
		if err != nil {
			t.Fatalf("validateAndPrepareInputs() error = %v, want nil", err)
		}

		if hashAlgo != "sha512" {
			t.Errorf("validateAndPrepareInputs() hashAlgo = %s, want sha512 (inferred from fingerprint)", hashAlgo)
		}
		if len(urls) != 1 {
			t.Fatalf("validateAndPrepareInputs() urls length = %d, want 1", len(urls))
		}
		if len(fingerprints) != 1 {
			t.Fatalf("validateAndPrepareInputs() fingerprints length = %d, want 1", len(fingerprints))
		}
	})

	t.Run("infers hash algorithm from multiple fingerprints", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert1.crt,https://example.com/cert2.crt",
			Fingerprint:   "SHA512:AB:CD:EF,SHA512:12:34:56",
			HashAlgorithm: "sha256", // default value, should be overridden
		}

		hashAlgo, urls, fingerprints, err := validateAndPrepareInputs(opts)
		if err != nil {
			t.Fatalf("validateAndPrepareInputs() error = %v, want nil", err)
		}

		if hashAlgo != "sha512" {
			t.Errorf("validateAndPrepareInputs() hashAlgo = %s, want sha512 (inferred from fingerprints)", hashAlgo)
		}
		if len(urls) != 2 {
			t.Fatalf("validateAndPrepareInputs() urls length = %d, want 2", len(urls))
		}
		if len(fingerprints) != 2 {
			t.Fatalf("validateAndPrepareInputs() fingerprints length = %d, want 2", len(fingerprints))
		}
	})

	t.Run("rejects mixed hash algorithms in fingerprints", func(t *testing.T) {
		opts := &AddOptions{
			VendorID:      "STM",
			URL:           "https://example.com/cert1.crt,https://example.com/cert2.crt",
			Fingerprint:   "SHA256:AB:CD:EF,SHA512:12:34:56",
			HashAlgorithm: "sha256",
		}

		_, _, _, err := validateAndPrepareInputs(opts)
		if err == nil {
			t.Fatal("validateAndPrepareInputs() error = nil, want error for mixed hash algorithms")
		}

		if !strings.Contains(err.Error(), "all fingerprints must use the same hash algorithm") {
			t.Errorf("validateAndPrepareInputs() error = %v, want error containing 'all fingerprints must use the same hash algorithm'", err)
		}
	})
}

func TestParseFingerprint(t *testing.T) {
	t.Run("parses valid SHA256 fingerprint", func(t *testing.T) {
		alg, hash, err := ParseFingerprint("SHA256:AB:CD:EF:01:23:45:67:89")
		if err != nil {
			t.Fatalf("ParseFingerprint() error = %v, want nil", err)
		}

		if alg != "sha256" {
			t.Errorf("ParseFingerprint() alg = %s, want sha256", alg)
		}
		if hash != "AB:CD:EF:01:23:45:67:89" {
			t.Errorf("ParseFingerprint() hash = %s, want AB:CD:EF:01:23:45:67:89", hash)
		}
	})

	t.Run("parses valid SHA1 fingerprint", func(t *testing.T) {
		alg, hash, err := ParseFingerprint("sha1:ab:cd:ef")
		if err != nil {
			t.Fatalf("ParseFingerprint() error = %v, want nil", err)
		}

		if alg != "sha1" {
			t.Errorf("ParseFingerprint() alg = %s, want sha1", alg)
		}
		if hash != "AB:CD:EF" {
			t.Errorf("ParseFingerprint() hash = %s, want AB:CD:EF", hash)
		}
	})

	t.Run("parses valid SHA256 fingerprint without colon", func(t *testing.T) {
		alg, hash, err := ParseFingerprint("sha256:abcdef")
		if err != nil {
			t.Fatalf("ParseFingerprint() error = %v, want nil", err)
		}

		if alg != "sha256" {
			t.Errorf("ParseFingerprint() alg = %s, want sha256", alg)
		}
		if hash != "AB:CD:EF" {
			t.Errorf("ParseFingerprint() hash = %s, want AB:CD:EF", hash)
		}
	})

	t.Run("rejects fingerprint without colon", func(t *testing.T) {
		_, _, err := ParseFingerprint("SHA256ABCDEF")
		if err == nil {
			t.Fatal("ParseFingerprint() error = nil, want error for missing colon")
		}

		if !strings.Contains(err.Error(), "must be in format HASH_ALG:HASH") {
			t.Errorf("ParseFingerprint() error = %v, want error containing 'must be in format HASH_ALG:HASH'", err)
		}
	})

	t.Run("rejects unsupported hash algorithm", func(t *testing.T) {
		_, _, err := ParseFingerprint("MD5:AB:CD:EF")
		if err == nil {
			t.Fatal("ParseFingerprint() error = nil, want error for unsupported algorithm")
		}

		if !strings.Contains(err.Error(), "unsupported hash algorithm") {
			t.Errorf("ParseFingerprint() error = %v, want error containing 'unsupported hash algorithm'", err)
		}
	})
}
