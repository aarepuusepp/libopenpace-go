package pace

import (
	"errors"
	"fmt"
)

// ErrUnsupportedProtocol identifies variants that must not run with this implementation.
var ErrUnsupportedProtocol = errors.New("unsupported PACE protocol")

// ValidateProtocol rejects incomplete IM/3DES implementations and unknown OIDs.
// The OID constants remain available for parsing and diagnosis.
func ValidateProtocol(protocol ProtocolOID) error {
	switch protocol {
	case OID_PACE_ECDH_GM_AES128, OID_PACE_ECDH_GM_AES192, OID_PACE_ECDH_GM_AES256,
		OID_PACE_DH_GM_AES128, OID_PACE_DH_GM_AES192, OID_PACE_DH_GM_AES256:
		return nil
	default:
		return fmt.Errorf("%w: %s; only Generic Mapping with AES is enabled (IM/3DES disabled)", ErrUnsupportedProtocol, protocol)
	}
}
