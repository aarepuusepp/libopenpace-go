package pace

import (
	"crypto/elliptic"
	"fmt"

	"github.com/aarepuusepp/libopenpace-go/crypto"
	"github.com/aarepuusepp/libopenpace-go/sm"
	"go.gnd.pw/crypto/brainpool"
)

var verboseMode bool

// SetVerbose enables or disables verbose debug logging for the PACE protocol.
func SetVerbose(enabled bool) {
	verboseMode = enabled
}

func logVerbose(format string, args ...interface{}) {
	if verboseMode {
		fmt.Printf(format, args...)
	}
}

// CardInterface defines the interface for smart card communication.
// This allows the PACE implementation to work with any card reader.
type CardInterface interface {
	// Transmit sends an APDU command and returns the response.
	Transmit(command []byte) ([]byte, error)
}

// EstablishPACE is a compatibility alias for PerformPACE. It always performs
// the real card exchange and mutual authentication; no simulated peer is used.
func EstablishPACE(card CardInterface, secret *PACESecret, protocol ProtocolOID, parameterID int) (*sm.Context, error) {
	return PerformPACE(card, secret, protocol, parameterID)
}

// setupDomainParameters sets up domain parameters based on parameter ID.
//
// BSI TR-03110 Part 3, Appendix A.3.1 standardized domain parameters:
//
//	 8 = secp192r1      9 = brainpoolP192r1
//	10 = secp224r1     11 = brainpoolP224r1
//	12 = secp256r1     13 = brainpoolP256r1
//	14 = brainpoolP320r1
//	15 = secp384r1     16 = brainpoolP384r1
//	17 = brainpoolP512r1
//	18 = secp521r1
func setupDomainParameters(ctx *PACEContext, parameterID int) error {
	keyAgreementType := ctx.Protocol.GetKeyAgreementType()

	if keyAgreementType == KeyAgreementECDH {
		var ecCurve elliptic.Curve
		var curveName string

		switch parameterID {
		case 12: // secp256r1 (NIST P-256)
			ecCurve = elliptic.P256()
			curveName = "secp256r1 (NIST P-256)"
		case 13: // brainpoolP256r1
			ecCurve = brainpool.P256r1()
			curveName = "brainpoolP256r1"
		case 15: // secp384r1 (NIST P-384)
			ecCurve = elliptic.P384()
			curveName = "secp384r1 (NIST P-384)"
		case 16: // brainpoolP384r1
			ecCurve = brainpool.P384r1()
			curveName = "brainpoolP384r1"
		case 18: // secp521r1 (NIST P-521)
			ecCurve = elliptic.P521()
			curveName = "secp521r1 (NIST P-521)"
		default:
			return fmt.Errorf("unsupported EC parameter ID: %d", parameterID)
		}

		ctx.DomainParams = &DomainParameters{
			Type:          DomainTypeEC,
			EllipticCurve: ecCurve,
		}
		logVerbose("[PACE] Using %s curve (ParamID=%d)\n", curveName, parameterID)
		return nil
	} else {
		// DH parameters
		params, err := crypto.GetStandardDHParameters("modp2048")
		if err != nil {
			return err
		}

		ctx.DomainParams = &DomainParameters{
			Type: DomainTypeDH,
			P:    params.P,
			Q:    params.Q,
			G:    params.G,
		}
	}

	return nil
}

// Session represents an established PACE session with Secure Messaging.
type Session struct {
	SMContext *sm.Context
	Card      CardInterface
}

// WrapAPDU wraps a command APDU with Secure Messaging.
//
// Parameters:
//   - cla, ins, p1, p2: APDU header
//   - data: Command data (can be empty)
//   - le: Expected response length
//
// Returns the wrapped APDU bytes.
func (s *Session) WrapAPDU(cla, ins, p1, p2 byte, data []byte, le int) ([]byte, error) {
	return s.SMContext.WrapCommand(cla, ins, p1, p2, data, le)
}

// UnwrapResponse unwraps a response APDU.
//
// Parameters:
//   - response: Protected response APDU
//
// Returns the plaintext data, status word, and error.
func (s *Session) UnwrapResponse(response []byte) ([]byte, uint16, error) {
	return s.SMContext.UnwrapResponse(response)
}

// TransmitSecure sends a protected APDU and returns the unprotected response.
//
// This is a convenience function that wraps, transmits, and unwraps in one call.
//
// Parameters:
//   - cla, ins, p1, p2: APDU header
//   - data: Command data
//   - le: Expected response length
//
// Returns the plaintext response data, status word, and error.
func (s *Session) TransmitSecure(cla, ins, p1, p2 byte, data []byte, le int) ([]byte, uint16, error) {
	// Wrap command
	wrappedCmd, err := s.WrapAPDU(cla, ins, p1, p2, data, le)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to wrap APDU: %w", err)
	}

	// Transmit to card
	response, err := s.Card.Transmit(wrappedCmd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to transmit APDU: %w", err)
	}

	// Unwrap response
	plainData, sw, err := s.UnwrapResponse(response)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unwrap response: %w", err)
	}

	return plainData, sw, nil
}
