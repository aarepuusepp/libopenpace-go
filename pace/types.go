package pace

import (
	"crypto/ecdh"
	"math/big"
)

// PACEContext holds the state for a PACE protocol session.
// It maintains all cryptographic material and protocol state throughout
// the PACE establishment process.
type PACEContext struct {
	// Protocol configuration
	Protocol      ProtocolOID       // PACE protocol variant (ECDH/DH, GM/IM/CAM)
	ParameterID   int               // Standardized domain parameter ID
	DomainParams  *DomainParameters // Domain parameters (curve or DH group)
	
	// Nonce (Step 1-2)
	Nonce         []byte            // Decrypted nonce from card
	
	// Mapping (Step 3A)
	MappedGenerator interface{}     // Mapped generator (EC point or DH element)
	
	// Key Agreement (Step 3B)
	EphemeralPrivateKey interface{} // Ephemeral private key (ECDH or DH)
	EphemeralPublicKey  interface{} // Ephemeral public key
	PeerPublicKey       interface{} // Peer's ephemeral public key
	SharedSecret        []byte      // Computed shared secret
	
	// Session Keys (Step 3C)
	EncryptionKey []byte            // K_enc for secure messaging
	MACKey        []byte            // K_mac for secure messaging
	
	// Authentication (Step 3D)
	AuthToken     []byte            // Our authentication token
	PeerAuthToken []byte            // Peer's authentication token
	
	// Secure Messaging state
	SM            *SMContext        // Secure messaging context
}

// PACESecret represents the shared secret used to establish PACE.
// For Estonian ID cards, this is typically the CAN (Card Access Number).
type PACESecret struct {
	Type  SecretType // Type of secret (CAN, PIN, MRZ, etc.)
	Value []byte     // Secret value
}

// SecretType identifies the type of PACE secret.
type SecretType int

const (
	SecretTypeCAN SecretType = iota // Card Access Number (6 digits)
	SecretTypePIN                    // Personal Identification Number
	SecretTypeMRZ                    // Machine Readable Zone
	SecretTypePUK                    // PIN Unblocking Key
)

// SMContext holds the Secure Messaging session state.
// It manages encryption/MAC keys and the send sequence counter.
type SMContext struct {
	EncryptionKey []byte      // K_enc for encrypting APDUs
	MACKey        []byte      // K_mac for MAC computation
	SSC           []byte      // Send Sequence Counter (8 bytes)
	CipherSuite   CipherSuite // Cipher suite (AES-128/192/256, 3DES)
}

// CipherSuite identifies the encryption and MAC algorithms.
type CipherSuite int

const (
	CipherSuiteAES128 CipherSuite = iota // AES-128-CBC + CMAC
	CipherSuiteAES192                     // AES-192-CBC + CMAC
	CipherSuiteAES256                     // AES-256-CBC + CMAC
	CipherSuite3DES                       // 3DES-CBC + Retail MAC
)

// KeyAgreementContext holds the state for key agreement operations.
// This is used during PACE Step 3B.
type KeyAgreementContext struct {
	Type          KeyAgreementType // ECDH or DH
	DomainParams  *DomainParameters
	PrivateKey    interface{} // *ecdh.PrivateKey or *big.Int
	PublicKey     interface{} // *ecdh.PublicKey or *big.Int
	SharedSecret  []byte
}

// KeyAgreementType identifies the key agreement algorithm.
type KeyAgreementType int

const (
	KeyAgreementECDH KeyAgreementType = iota // Elliptic Curve Diffie-Hellman
	KeyAgreementDH                            // Diffie-Hellman
)

// DomainParameters represents either EC or DH domain parameters.
type DomainParameters struct {
	Type DomainType // EC or DH
	
	// For EC (Elliptic Curve)
	Curve      ecdh.Curve // Standard curve (P-256, P-384, P-521, etc.)
	CurveName  string     // Curve name for custom curves
	
	// For DH (Diffie-Hellman)
	P *big.Int // Prime modulus
	Q *big.Int // Prime order of subgroup
	G *big.Int // Generator
}

// DomainType identifies the type of domain parameters.
type DomainType int

const (
	DomainTypeEC DomainType = iota // Elliptic Curve
	DomainTypeDH                    // Diffie-Hellman
)

// ProtocolOID identifies the PACE protocol variant.
// These OIDs are defined in BSI TR-03110.
type ProtocolOID string

const (
	// PACE with ECDH and Generic Mapping
	OID_PACE_ECDH_GM_AES128 ProtocolOID = "0.4.0.127.0.7.2.2.4.1.2"
	OID_PACE_ECDH_GM_AES192 ProtocolOID = "0.4.0.127.0.7.2.2.4.1.3"
	OID_PACE_ECDH_GM_AES256 ProtocolOID = "0.4.0.127.0.7.2.2.4.1.4"
	OID_PACE_ECDH_GM_3DES   ProtocolOID = "0.4.0.127.0.7.2.2.4.1.1"
	
	// PACE with ECDH and Integrated Mapping
	OID_PACE_ECDH_IM_AES128 ProtocolOID = "0.4.0.127.0.7.2.2.4.2.2"
	OID_PACE_ECDH_IM_AES192 ProtocolOID = "0.4.0.127.0.7.2.2.4.2.3"
	OID_PACE_ECDH_IM_AES256 ProtocolOID = "0.4.0.127.0.7.2.2.4.2.4"
	OID_PACE_ECDH_IM_3DES   ProtocolOID = "0.4.0.127.0.7.2.2.4.2.1"
	
	// PACE with DH and Generic Mapping
	OID_PACE_DH_GM_AES128 ProtocolOID = "0.4.0.127.0.7.2.2.4.3.2"
	OID_PACE_DH_GM_AES192 ProtocolOID = "0.4.0.127.0.7.2.2.4.3.3"
	OID_PACE_DH_GM_AES256 ProtocolOID = "0.4.0.127.0.7.2.2.4.3.4"
	OID_PACE_DH_GM_3DES   ProtocolOID = "0.4.0.127.0.7.2.2.4.3.1"
	
	// PACE with DH and Integrated Mapping
	OID_PACE_DH_IM_AES128 ProtocolOID = "0.4.0.127.0.7.2.2.4.4.2"
	OID_PACE_DH_IM_AES192 ProtocolOID = "0.4.0.127.0.7.2.2.4.4.3"
	OID_PACE_DH_IM_AES256 ProtocolOID = "0.4.0.127.0.7.2.2.4.4.4"
	OID_PACE_DH_IM_3DES   ProtocolOID = "0.4.0.127.0.7.2.2.4.4.1"
)

// MappingType identifies the domain parameter mapping method.
type MappingType int

const (
	MappingGeneric    MappingType = iota // Generic Mapping (GM)
	MappingIntegrated                     // Integrated Mapping (IM)
	MappingCAM                            // Chip Authentication Mapping (CAM)
)

// GetCipherSuite returns the cipher suite for a protocol OID.
func (oid ProtocolOID) GetCipherSuite() CipherSuite {
	switch oid {
	case OID_PACE_ECDH_GM_AES128, OID_PACE_ECDH_IM_AES128,
		OID_PACE_DH_GM_AES128, OID_PACE_DH_IM_AES128:
		return CipherSuiteAES128
	case OID_PACE_ECDH_GM_AES192, OID_PACE_ECDH_IM_AES192,
		OID_PACE_DH_GM_AES192, OID_PACE_DH_IM_AES192:
		return CipherSuiteAES192
	case OID_PACE_ECDH_GM_AES256, OID_PACE_ECDH_IM_AES256,
		OID_PACE_DH_GM_AES256, OID_PACE_DH_IM_AES256:
		return CipherSuiteAES256
	case OID_PACE_ECDH_GM_3DES, OID_PACE_ECDH_IM_3DES,
		OID_PACE_DH_GM_3DES, OID_PACE_DH_IM_3DES:
		return CipherSuite3DES
	default:
		return CipherSuiteAES128 // Default
	}
}

// GetKeyAgreementType returns the key agreement type for a protocol OID.
func (oid ProtocolOID) GetKeyAgreementType() KeyAgreementType {
	switch oid {
	case OID_PACE_ECDH_GM_AES128, OID_PACE_ECDH_GM_AES192, OID_PACE_ECDH_GM_AES256, OID_PACE_ECDH_GM_3DES,
		OID_PACE_ECDH_IM_AES128, OID_PACE_ECDH_IM_AES192, OID_PACE_ECDH_IM_AES256, OID_PACE_ECDH_IM_3DES:
		return KeyAgreementECDH
	case OID_PACE_DH_GM_AES128, OID_PACE_DH_GM_AES192, OID_PACE_DH_GM_AES256, OID_PACE_DH_GM_3DES,
		OID_PACE_DH_IM_AES128, OID_PACE_DH_IM_AES192, OID_PACE_DH_IM_AES256, OID_PACE_DH_IM_3DES:
		return KeyAgreementDH
	default:
		return KeyAgreementECDH // Default
	}
}

// GetMappingType returns the mapping type for a protocol OID.
func (oid ProtocolOID) GetMappingType() MappingType {
	switch oid {
	case OID_PACE_ECDH_GM_AES128, OID_PACE_ECDH_GM_AES192, OID_PACE_ECDH_GM_AES256, OID_PACE_ECDH_GM_3DES,
		OID_PACE_DH_GM_AES128, OID_PACE_DH_GM_AES192, OID_PACE_DH_GM_AES256, OID_PACE_DH_GM_3DES:
		return MappingGeneric
	case OID_PACE_ECDH_IM_AES128, OID_PACE_ECDH_IM_AES192, OID_PACE_ECDH_IM_AES256, OID_PACE_ECDH_IM_3DES,
		OID_PACE_DH_IM_AES128, OID_PACE_DH_IM_AES192, OID_PACE_DH_IM_AES256, OID_PACE_DH_IM_3DES:
		return MappingIntegrated
	default:
		return MappingGeneric // Default
	}
}

// ToOIDSlice converts the OID string to a slice of integers for ASN.1 encoding.
func (p ProtocolOID) ToOIDSlice() []int {
	// Parse OID string like "0.4.0.127.0.7.2.2.4.2.2"
	oidStr := string(p)
	var result []int
	current := 0
	
	for i := 0; i < len(oidStr); i++ {
		if oidStr[i] == '.' {
			result = append(result, current)
			current = 0
		} else if oidStr[i] >= '0' && oidStr[i] <= '9' {
			current = current*10 + int(oidStr[i]-'0')
		}
	}
	// Add last component
	result = append(result, current)
	
	return result
}

