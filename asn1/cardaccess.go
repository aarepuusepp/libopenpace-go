package asn1

import (
	"encoding/asn1"
	"fmt"
)

// CardAccess represents the parsed EF.CardAccess file.
// EF.CardAccess contains security information about supported protocols.
type CardAccess struct {
	SecurityInfos []SecurityInfo
}

// SecurityInfo represents a security information object.
type SecurityInfo struct {
	Protocol   asn1.ObjectIdentifier
	Parameters interface{} // Protocol-specific parameters
}

// PACEInfo represents PACE protocol information from EF.CardAccess.
type PACEInfo struct {
	Protocol      string // Protocol OID as string
	Version       int    // Protocol version
	ParameterID   int    // Standardized domain parameter ID
	DomainParams  []byte // Optional explicit domain parameters
}

// ParseCardAccess parses EF.CardAccess data.
//
// EF.CardAccess structure (simplified):
//   SecurityInfos ::= SET OF SecurityInfo
//   SecurityInfo ::= SEQUENCE {
//     protocol OBJECT IDENTIFIER,
//     requiredData ANY DEFINED BY protocol,
//     optionalData ANY DEFINED BY protocol OPTIONAL
//   }
//
// Parameters:
//   - data: Raw EF.CardAccess bytes
//
// Returns the parsed CardAccess structure.
//
// Reference: BSI TR-03110 Section 3.1
func ParseCardAccess(data []byte) (*CardAccess, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty CardAccess data")
	}
	
	// For a simplified implementation, we'll parse the basic structure
	// A full implementation would need to handle all SecurityInfo types
	
	var securityInfos []interface{}
	rest, err := asn1.Unmarshal(data, &securityInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CardAccess: %w", err)
	}
	
	if len(rest) > 0 {
		// There's trailing data, which might be okay
	}
	
	ca := &CardAccess{
		SecurityInfos: make([]SecurityInfo, 0),
	}
	
	// Parse each SecurityInfo
	for _, info := range securityInfos {
		// Each info should be a sequence
		infoBytes, ok := info.([]byte)
		if !ok {
			continue
		}
		
		var si SecurityInfo
		_, err := asn1.Unmarshal(infoBytes, &si)
		if err != nil {
			// Skip unparseable entries
			continue
		}
		
		ca.SecurityInfos = append(ca.SecurityInfos, si)
	}
	
	return ca, nil
}

// GetPACEInfo extracts PACE information from CardAccess.
//
// Returns the first PACE protocol found, or nil if none exists.
func (ca *CardAccess) GetPACEInfo() *PACEInfo {
	for _, si := range ca.SecurityInfos {
		// Check if this is a PACE protocol
		// PACE OIDs start with 0.4.0.127.0.7.2.2.4
		oidStr := si.Protocol.String()
		
		// Check if OID starts with PACE prefix
		if len(oidStr) >= 19 && oidStr[:19] == "0.4.0.127.0.7.2.2.4" {
			// This is a PACE protocol
			return &PACEInfo{
				Protocol:    oidStr,
				Version:     2, // Default to version 2
				ParameterID: 0, // Would need to parse from parameters
			}
		}
	}
	
	return nil
}

// CreateDefaultCardAccess creates a default CardAccess for testing.
//
// This creates a CardAccess with PACE ECDH GM AES-128 using P-256.
func CreateDefaultCardAccess() *CardAccess {
	// PACE ECDH GM AES-128 OID: 0.4.0.127.0.7.2.2.4.1.2
	oid := asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2}
	
	return &CardAccess{
		SecurityInfos: []SecurityInfo{
			{
				Protocol:   oid,
				Parameters: nil,
			},
		},
	}
}

// GetProtocolOID returns the protocol OID as a string.
func (pi *PACEInfo) GetProtocolOID() string {
	return pi.Protocol
}

// GetParameterID returns the standardized domain parameter ID.
//
// Common parameter IDs:
//   - 0: Explicit parameters in CardAccess
//   - 8: NIST P-256 (secp256r1)
//   - 9: BrainpoolP256r1
//   - 10: NIST P-384 (secp384r1)
//   - 11: BrainpoolP384r1
//   - 12: NIST P-521 (secp521r1)
//   - 13: BrainpoolP512r1
func (pi *PACEInfo) GetParameterID() int {
	return pi.ParameterID
}

// SetParameterID sets the standardized domain parameter ID.
func (pi *PACEInfo) SetParameterID(id int) {
	pi.ParameterID = id
}

