package format

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"go.yaml.in/yaml/v4"
)

// Formatter handles YAML formatting operations.
type Formatter struct{}

// NewFormatter creates a new YAML formatter.
func NewFormatter() *Formatter {
	return &Formatter{}
}

// NeedsFormatting checks if a file needs formatting without modifying it.
//
// It returns true if the file would be changed by formatting, false otherwise.
//
// Example:
//
//	formatter := format.NewFormatter()
//	needs, err := formatter.NeedsFormatting(".tpm-roots.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if needs {
//	    fmt.Println("File needs formatting")
//	}
func (f *Formatter) NeedsFormatting(inputPath string) (bool, error) {
	cfg, err := config.LoadConfig(inputPath)
	if err != nil {
		return false, fmt.Errorf("failed to load config: %w", err)
	}

	f.applyFormatting(cfg)

	formattedData, err := f.marshalWithQuotes(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to marshal YAML: %w", err)
	}

	originalData, err := utils.ReadFile(inputPath)
	if err != nil {
		return false, fmt.Errorf("failed to read original file: %w", err)
	}

	formattedWithMarker := f.ensureYAMLDocumentMarker(formattedData)
	return string(formattedWithMarker) != string(originalData), nil
}

// FormatFile applies formatting rules to a TPM roots configuration file.
//
// The formatting includes:
//   - Adding YAML document marker (---) at the beginning if missing
//   - Sorting vendors by ID (alphabetical)
//   - Sorting certificates within each vendor by name (alphabetical)
//   - URL-encoding certificate URLs
//   - Formatting fingerprints to uppercase with colon separators
//   - Adding double quotes to all string values
//
// Example:
//
//	formatter := format.NewFormatter()
//	err := formatter.FormatFile(".tpm-roots.yaml", ".tpm-roots.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (f *Formatter) FormatFile(inputPath, outputPath string) error {
	cfg, err := config.LoadConfig(inputPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	f.applyFormatting(cfg)

	yamlData, err := f.marshalWithQuotes(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	yamlData = f.ensureYAMLDocumentMarker(yamlData)

	if err := os.WriteFile(outputPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// applyFormatting applies all formatting rules to the configuration.
func (f *Formatter) applyFormatting(cfg *config.TPMRootsConfig) {
	sort.Slice(cfg.Vendors, func(i, j int) bool {
		return cfg.Vendors[i].ID < cfg.Vendors[j].ID
	})

	for i := range cfg.Vendors {
		sort.Slice(cfg.Vendors[i].Certificates, func(a, b int) bool {
			return cfg.Vendors[i].Certificates[a].Name < cfg.Vendors[i].Certificates[b].Name
		})

		for j := range cfg.Vendors[i].Certificates {
			cert := &cfg.Vendors[i].Certificates[j]
			cert.URL = f.encodeURL(cert.URL)
			cert.URI = f.encodeURI(cert.URI)

			fp := &cert.Validation.Fingerprint
			fp.SHA1 = f.formatFingerprint(fp.SHA1)
			fp.SHA256 = f.formatFingerprint(fp.SHA256)
			fp.SHA384 = f.formatFingerprint(fp.SHA384)
			fp.SHA512 = f.formatFingerprint(fp.SHA512)
		}
	}
}

func (f *Formatter) encodeURI(rawURI string) string {
	if rawURI == "" {
		return rawURI
	}
	parsedURI, err := url.Parse(rawURI)
	if err != nil {
		return rawURI
	}
	if parsedURI.Scheme == "https" {
		return f.encodeURL(rawURI)
	}
	return rawURI
}

// encodeURL ensures the URL is properly URL-encoded.
func (f *Formatter) encodeURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	return parsedURL.String()
}

// formatFingerprint formats a fingerprint to uppercase with colon separators.
func (f *Formatter) formatFingerprint(fp string) string {
	if fp == "" {
		return fp
	}

	cleaned := strings.ReplaceAll(fp, ":", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ToUpper(cleaned)

	if len(cleaned) == 0 {
		return fp
	}

	var result strings.Builder
	for i := 0; i < len(cleaned); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		if i+2 <= len(cleaned) {
			result.WriteString(cleaned[i : i+2])
		} else {
			result.WriteString(cleaned[i:])
		}
	}

	return result.String()
}

// marshalWithQuotes marshals the config to YAML with quoted strings.
func (f *Formatter) marshalWithQuotes(cfg *config.TPMRootsConfig) ([]byte, error) {
	var node yaml.Node
	if err := node.Encode(cfg); err != nil {
		return nil, err
	}

	f.addQuotesToStrings(&node)

	return yaml.Marshal(&node)
}

// addQuotesToStrings recursively adds quotes to all string scalar nodes (values only, not keys).
func (f *Formatter) addQuotesToStrings(node *yaml.Node) {
	if node == nil {
		return
	}

	// For mapping nodes, only quote values (not keys)
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			// node.Content[i] is the key, node.Content[i+1] is the value
			// Recurse on both, but only quote value scalars
			f.addQuotesToStrings(node.Content[i+1])
		}
		return
	}

	// For scalar nodes (values), add quotes
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		node.Style = yaml.DoubleQuotedStyle
	}

	// For sequences and other nodes, recurse
	for _, child := range node.Content {
		f.addQuotesToStrings(child)
	}
}

// ensureYAMLDocumentMarker ensures the YAML data starts with --- on the first line.
func (f *Formatter) ensureYAMLDocumentMarker(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return append([]byte("---\n"), data...)
	}

	// Check that first line is exactly "---" without any leading/trailing spaces
	if lines[0] != "---" {
		return append([]byte("---\n"), data...)
	}

	return data
}
