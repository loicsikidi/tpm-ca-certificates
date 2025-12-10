package validate

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"go.yaml.in/yaml/v4"
)

// ValidationError represents a single validation error with its line number.
type ValidationError struct {
	Line    int
	Message string
}

// YAMLValidator handles YAML validation operations.
type YAMLValidator struct {
	errors      []ValidationError
	maxErrors   int
	lineMapping map[string]int
}

// NewYAMLValidator creates a new YAML validator.
func NewYAMLValidator() *YAMLValidator {
	return &YAMLValidator{
		errors:      make([]ValidationError, 0),
		maxErrors:   10,
		lineMapping: make(map[string]int),
	}
}

// ValidateFile validates a TPM roots configuration file.
//
// It checks:
//   - File starts with YAML document marker (---)
//   - Vendor IDs are valid according to TCG TPM Vendor ID Registry
//   - No duplicate vendor IDs
//   - Vendors are sorted alphabetically by ID
//   - Certificates within each vendor are sorted alphabetically by name
//   - No duplicate certificates
//   - URLs are properly URL-encoded and use HTTPS scheme
//   - Fingerprints are formatted in uppercase with colon separators
//   - String values are double-quoted
//
// Returns the list of validation errors (max 10).
//
// Example:
//
//	validator := validate.NewValidator()
//	errors := validator.ValidateFile(".tpm-roots.yaml")
//	if len(errors) > 0 {
//	    for _, err := range errors {
//	        fmt.Printf("Line %d: %s\n", err.Line, err.Message)
//	    }
//	    os.Exit(1)
//	}
func (v *YAMLValidator) ValidateFile(path string) ([]ValidationError, error) {
	data, err := utils.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	v.validateYAMLDocumentMarker(data)

	cfg, err := config.LoadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if err := v.buildLineMapping(data); err != nil {
		return nil, fmt.Errorf("failed to parse YAML for line mapping: %w", err)
	}

	v.validateVendorIDs(cfg)
	v.validateDuplicateVendorIDs(cfg)
	v.validateVendorsSorting(cfg)
	v.validateCertificatesSorting(cfg)
	v.validateDuplicateCertificates(cfg)
	v.validateURLEncoding(cfg)
	v.validateFingerprintFormat(cfg)
	v.validateQuotes(data)

	return v.errors, nil
}

// validateYAMLDocumentMarker checks that the file starts with ---.
func (v *YAMLValidator) validateYAMLDocumentMarker(data []byte) {
	if len(v.errors) >= v.maxErrors {
		return
	}

	lines := strings.Split(string(data), "\n")
	// Check that first line is exactly "---" without any leading/trailing spaces
	if len(lines) == 0 || lines[0] != "---" {
		v.errors = append(v.errors, ValidationError{
			Line:    1,
			Message: "file must start with YAML document marker '---' on the first line",
		})
	}
}

// buildLineMapping creates a mapping from YAML paths to line numbers.
func (v *YAMLValidator) buildLineMapping(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return err
	}

	v.walkNode(&node, "")
	return nil
}

// walkNode recursively walks the YAML node tree to build line mappings.
func (v *YAMLValidator) walkNode(node *yaml.Node, path string) {
	if node == nil {
		return
	}

	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		v.walkNode(node.Content[0], path)
		return
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			newPath := path
			if newPath != "" {
				newPath += "."
			}
			newPath += key

			v.lineMapping[newPath] = keyNode.Line

			if valueNode.Kind == yaml.SequenceNode {
				for j, item := range valueNode.Content {
					itemPath := fmt.Sprintf("%s[%d]", newPath, j)
					v.lineMapping[itemPath] = item.Line
					v.walkNode(item, itemPath)
				}
			} else {
				v.walkNode(valueNode, newPath)
			}
		}
	}
}

// addError adds a validation error if the limit hasn't been reached.
func (v *YAMLValidator) addError(path, message string) {
	if len(v.errors) >= v.maxErrors {
		return
	}

	line := v.lineMapping[path]
	if line == 0 {
		line = 1
	}

	v.errors = append(v.errors, ValidationError{
		Line:    line,
		Message: message,
	})
}

// validateVendorIDs checks that all vendor IDs are valid according to TCG registry.
func (v *YAMLValidator) validateVendorIDs(cfg *config.TPMRootsConfig) {
	for i, vendor := range cfg.Vendors {
		if !vendors.IsValidVendorID(vendor.ID) {
			path := fmt.Sprintf("vendors[%d].id", i)
			v.addError(path, fmt.Sprintf("invalid vendor ID %q: not found in TCG TPM Vendor ID Registry", vendor.ID))
		}
	}
}

// validateDuplicateVendorIDs checks for duplicate vendor IDs.
func (v *YAMLValidator) validateDuplicateVendorIDs(cfg *config.TPMRootsConfig) {
	seenIDs := make(map[string]int)

	for i, vendor := range cfg.Vendors {
		if firstIdx, exists := seenIDs[vendor.ID]; exists {
			path := fmt.Sprintf("vendors[%d].id", i)
			v.addError(path, fmt.Sprintf("duplicate vendor ID %q (first defined at vendors[%d])",
				vendor.ID, firstIdx))
		} else {
			seenIDs[vendor.ID] = i
		}
	}
}

// validateVendorsSorting checks that vendors are sorted by ID.
func (v *YAMLValidator) validateVendorsSorting(cfg *config.TPMRootsConfig) {
	vendorIDs := make([]string, len(cfg.Vendors))
	for i, vendor := range cfg.Vendors {
		vendorIDs[i] = vendor.ID
	}

	sortedIDs := make([]string, len(vendorIDs))
	copy(sortedIDs, vendorIDs)
	sort.Strings(sortedIDs)

	for i := range vendorIDs {
		if vendorIDs[i] != sortedIDs[i] {
			path := fmt.Sprintf("vendors[%d].id", i)
			v.addError(path, fmt.Sprintf("vendors not sorted by ID: expected %q at position %d, got %q",
				sortedIDs[i], i, vendorIDs[i]))
		}
	}
}

// validateCertificatesSorting checks that certificates are sorted by name within each vendor.
func (v *YAMLValidator) validateCertificatesSorting(cfg *config.TPMRootsConfig) {
	for i, vendor := range cfg.Vendors {
		certNames := make([]string, len(vendor.Certificates))
		for j, cert := range vendor.Certificates {
			certNames[j] = cert.Name
		}

		sortedNames := make([]string, len(certNames))
		copy(sortedNames, certNames)
		sort.Strings(sortedNames)

		for j := range certNames {
			if certNames[j] != sortedNames[j] {
				path := fmt.Sprintf("vendors[%d].certificates[%d].name", i, j)
				v.addError(path, fmt.Sprintf("certificates not sorted by name in vendor %q: expected %q at position %d, got %q",
					vendor.ID, sortedNames[j], j, certNames[j]))
			}
		}
	}
}

// validateDuplicateCertificates checks for duplicate certificates within each vendor by URL and fingerprint.
func (v *YAMLValidator) validateDuplicateCertificates(cfg *config.TPMRootsConfig) {
	for i, vendor := range cfg.Vendors {
		for j, cert := range vendor.Certificates {
			// Check against all previous certificates in the same vendor
			prevCerts := vendor.Certificates[:j]

			if ContainsCertificate(prevCerts, cert) {
				path := fmt.Sprintf("vendors[%d].certificates[%d]", i, j)
				v.addError(path, fmt.Sprintf("duplicate certificate %q in vendor %q",
					cert.Name, vendor.ID))
			}
		}
	}
}

// validateURLEncoding checks that URLs are properly encoded.
func (v *YAMLValidator) validateURLEncoding(cfg *config.TPMRootsConfig) {
	for i, vendor := range cfg.Vendors {
		for j, cert := range vendor.Certificates {
			parsedURL, err := url.Parse(cert.URL)
			if err != nil {
				path := fmt.Sprintf("vendors[%d].certificates[%d].url", i, j)
				v.addError(path, fmt.Sprintf("invalid URL: %v", err))
				continue
			}

			if parsedURL.Scheme != "https" {
				path := fmt.Sprintf("vendors[%d].certificates[%d].url", i, j)
				v.addError(path, fmt.Sprintf("URL must use HTTPS scheme: got %q", parsedURL.Scheme))
				continue
			}

			encoded := parsedURL.String()
			if encoded != cert.URL {
				path := fmt.Sprintf("vendors[%d].certificates[%d].url", i, j)
				v.addError(path, fmt.Sprintf("URL not properly encoded: got %q, expected %q", cert.URL, encoded))
			}
		}
	}
}

// validateFingerprintFormat checks that fingerprints are uppercase with colons.
func (v *YAMLValidator) validateFingerprintFormat(cfg *config.TPMRootsConfig) {
	for i, vendor := range cfg.Vendors {
		for j, cert := range vendor.Certificates {
			fp := cert.Validation.Fingerprint

			if fp.SHA1 != "" && !fingerprint.IsValid(fp.SHA1) {
				path := fmt.Sprintf("vendors[%d].certificates[%d].validation.fingerprint.sha1", i, j)
				v.addError(path, fmt.Sprintf("fingerprint not in uppercase with colons: got %q", fp.SHA1))
			}

			if fp.SHA256 != "" && !fingerprint.IsValid(fp.SHA256) {
				path := fmt.Sprintf("vendors[%d].certificates[%d].validation.fingerprint.sha256", i, j)
				v.addError(path, fmt.Sprintf("fingerprint not in uppercase with colons: got %q", fp.SHA256))
			}

			if fp.SHA384 != "" && !fingerprint.IsValid(fp.SHA384) {
				path := fmt.Sprintf("vendors[%d].certificates[%d].validation.fingerprint.sha384", i, j)
				v.addError(path, fmt.Sprintf("fingerprint not in uppercase with colons: got %q", fp.SHA384))
			}

			if fp.SHA512 != "" && !fingerprint.IsValid(fp.SHA512) {
				path := fmt.Sprintf("vendors[%d].certificates[%d].validation.fingerprint.sha512", i, j)
				v.addError(path, fmt.Sprintf("fingerprint not in uppercase with colons: got %q", fp.SHA512))
			}
		}
	}
}

// validateQuotes checks that string values are double-quoted in the YAML.
func (v *YAMLValidator) validateQuotes(data []byte) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return
	}

	v.checkQuotes(&node, "")
}

// checkQuotes recursively checks that scalar string values are quoted.
func (v *YAMLValidator) checkQuotes(node *yaml.Node, path string) {
	if node == nil {
		return
	}

	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		v.checkQuotes(node.Content[0], path)
		return
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			newPath := path
			if newPath != "" {
				newPath += "."
			}
			newPath += key

			if valueNode.Kind == yaml.SequenceNode {
				for j, item := range valueNode.Content {
					itemPath := fmt.Sprintf("%s[%d]", newPath, j)
					v.checkQuotes(item, itemPath)
				}
			} else if valueNode.Kind == yaml.ScalarNode && valueNode.Tag == "!!str" {
				if valueNode.Style != yaml.DoubleQuotedStyle {
					if len(v.errors) < v.maxErrors {
						v.errors = append(v.errors, ValidationError{
							Line:    valueNode.Line,
							Message: fmt.Sprintf("string value not double-quoted at %s: %q", newPath, valueNode.Value),
						})
					}
				}
			} else {
				v.checkQuotes(valueNode, newPath)
			}
		}
	}
}
