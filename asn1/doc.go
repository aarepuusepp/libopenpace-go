// Package asn1 provides ASN.1 parsing for smart card data structures.
//
// This package handles:
//   - EF.CardAccess parsing (PACEInfo, SecurityInfos)
//   - Domain parameter extraction
//   - Protocol OID identification
//   - Parameter ID resolution
//
// EF.CardAccess contains the security information required to establish
// a PACE session, including supported protocols, domain parameters, and
// cipher suites.
//
// Example usage:
//
//	cardAccess, err := asn1.ParseCardAccess(data)
//	paceInfo := cardAccess.GetPACEInfo()
//	domainParams := paceInfo.GetDomainParameters()
//
// References:
//   - BSI TR-03110: EF.CardAccess structure
//   - ISO/IEC 7816-4: File structures
package asn1

