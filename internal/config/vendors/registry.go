package vendors

import (
	"fmt"
	"slices"
)

// TPM Vendor IDs from the TCG registry.
//
// Source: TCG TPM Vendor ID Registry Family 1.2 and 2.0, Version 1.07, Revision 0.02
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
const (
	AMD  ID = "AMD"
	ANT  ID = "ANT"
	ATML ID = "ATML"
	BRCM ID = "BRCM"
	CSCO ID = "CSCO"
	FLYS ID = "FLYS"
	GOOG ID = "GOOG"
	HPI  ID = "HPI"
	HPE  ID = "HPE"
	HISI ID = "HISI"
	IBM  ID = "IBM"
	IFX  ID = "IFX"
	INTC ID = "INTC"
	LEN  ID = "LEN"
	MSFT ID = "MSFT"
	NSG  ID = "NSG"
	NSM  ID = "NSM"
	NTC  ID = "NTC"
	NTZ  ID = "NTZ"
	QCOM ID = "QCOM"
	ROCC ID = "ROCC"
	SEAL ID = "SEAL"
	SECE ID = "SECE"
	SMSN ID = "SMSN"
	SMSC ID = "SMSC"
	SNS  ID = "SNS"
	STM  ID = "STM"
	TXN  ID = "TXN"
	WEC  ID = "WEC"
)

// ValidVendorIDs contains the list of valid TPM vendor IDs from the TCG registry.
var ValidVendorIDs = []ID{
	AMD,
	ANT,
	ATML,
	BRCM,
	CSCO,
	FLYS,
	GOOG,
	HPI,
	HPE,
	HISI,
	IBM,
	IFX,
	INTC,
	LEN,
	MSFT,
	NSG,
	NSM,
	NTC,
	NTZ,
	QCOM,
	ROCC,
	SEAL,
	SECE,
	SMSN,
	SMSC,
	SNS,
	STM,
	TXN,
	WEC,
}

// IsValidVendorID checks if the provided vendor ID is in the TCG registry.
//
// Example:
//
//	if !vendors.IsValidVendorID("STM") {
//	    return fmt.Errorf("invalid vendor ID")
//	}
func IsValidVendorID(id string) bool {
	return slices.Contains(ValidVendorIDs, ID(id))
}

// ValidateVendorID returns an error if the vendor ID is not valid.
//
// Example:
//
//	if err := vendors.ValidateVendorID("INVALID"); err != nil {
//	    log.Fatal(err)
//	}
func ValidateVendorID(id string) error {
	if !IsValidVendorID(id) {
		return fmt.Errorf("invalid vendor ID %q: not found in TCG TPM Vendor ID Registry", id)
	}
	return nil
}
