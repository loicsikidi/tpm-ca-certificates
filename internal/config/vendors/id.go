package vendors

import "fmt"

// ID represents a TPM vendor ID from the TCG registry.
//
// Source: TCG TPM Vendor ID Registry Family 1.2 and 2.0, Version 1.07, Revision 0.02
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
type ID string

// Validate checks if the vendor ID is in the TCG registry.
//
// Example:
//
//	id := vendors.ID("STM")
//	if err := id.Validate(); err != nil {
//	    log.Fatal(err)
//	}
func (id ID) Validate() error {
	if !IsValidVendorID(string(id)) {
		return fmt.Errorf("invalid vendor ID %q: not found in TCG TPM Vendor ID Registry", id)
	}
	return nil
}

// String returns the string representation of the vendor ID.
func (id ID) String() string {
	return string(id)
}
