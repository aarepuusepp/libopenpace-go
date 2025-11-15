package pace

import "fmt"

// AESSuite represents the AES key size
type AESSuite int

const (
	AES128 AESSuite = 128
	AES192 AESSuite = 192
	AES256 AESSuite = 256
)

// SelectSuiteFromOID determines the AES suite from the PACE OID
func SelectSuiteFromOID(oid ProtocolOID) (AESSuite, error) {
	// Check cipher suite from OID
	switch oid {
	case OID_PACE_ECDH_GM_AES128, OID_PACE_ECDH_IM_AES128,
		OID_PACE_DH_GM_AES128, OID_PACE_DH_IM_AES128:
		return AES128, nil
	case OID_PACE_ECDH_GM_AES192, OID_PACE_ECDH_IM_AES192,
		OID_PACE_DH_GM_AES192, OID_PACE_DH_IM_AES192:
		return AES192, nil
	case OID_PACE_ECDH_GM_AES256, OID_PACE_ECDH_IM_AES256,
		OID_PACE_DH_GM_AES256, OID_PACE_DH_IM_AES256:
		return AES256, nil
	default:
		return 0, fmt.Errorf("unsupported PACE OID: %s", oid)
	}
}

// GetKeyLength returns the key length in bytes for the AES suite
func (s AESSuite) GetKeyLength() int {
	return int(s) / 8 // 128→16, 192→24, 256→32
}

// String returns a string representation of the AES suite
func (s AESSuite) String() string {
	switch s {
	case AES128:
		return "AES-128"
	case AES192:
		return "AES-192"
	case AES256:
		return "AES-256"
	default:
		return fmt.Sprintf("AES-%d", s)
	}
}

