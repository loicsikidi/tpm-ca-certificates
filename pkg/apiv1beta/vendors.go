package apiv1beta

import "github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"

// VendorID represents a TPM vendor ID from the TCG registry.
//
// Source: TCG TPM Vendor ID Registry Family 1.2 and 2.0, Version 1.07, Revision 0.02
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
type VendorID = vendors.ID

// TPM Vendor ID constants from the TCG registry.
//
// Source: TCG TPM Vendor ID Registry Family 1.2 and 2.0, Version 1.07, Revision 0.02
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf
// Vendor IDs not currently used are commented out.
const (
	// AMD  = vendors.AMD
	// ANT  = vendors.ANT
	// ATML = vendors.ATML
	// BRCM = vendors.BRCM
	// CSCO = vendors.CSCO
	// FLYS = vendors.FLYS
	// GOOG = vendors.GOOG
	// HPI  = vendors.HPI
	// HPE  = vendors.HPE
	// HISI = vendors.HISI
	// IBM  = vendors.IBM
	IFX  = vendors.IFX
	INTC = vendors.INTC
	// LEN  = vendors.LEN
	// MSFT = vendors.MSFT
	// NSG  = vendors.NSG
	// NSM  = vendors.NSM
	NTC = vendors.NTC
	// NTZ  = vendors.NTZ
	// QCOM = vendors.QCOM
	// ROCC = vendors.ROCC
	// SEAL = vendors.SEAL
	// SECE = vendors.SECE
	// SMSN = vendors.SMSN
	// SMSC = vendors.SMSC
	// SNS  = vendors.SNS
	STM = vendors.STM
	// TXN  = vendors.TXN
	// WEC  = vendors.WEC
)

// ValidVendorIDs contains the list of valid TPM vendor IDs from the TCG registry.
var ValidVendorIDs = vendors.ValidVendorIDs
