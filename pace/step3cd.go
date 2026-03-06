package pace

import (
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/aarepuusepp/libopenpace-go/crypto"
	"github.com/aarepuusepp/libopenpace-go/kdf"
)

// PACE_STEP3C_derive_keys implements PACE Step 3C: Derive Session Keys.
//
// Derives K_enc and K_mac from the shared secret using KDF.
// K_enc = KDF_Enc(sharedSecret) — counter=1
// K_mac = KDF_MAC(sharedSecret) — counter=2
//
// Reference: BSI TR-03110 v2.21 Section 4.4.3
func PACE_STEP3C_derive_keys(ctx *PACEContext) error {
	if len(ctx.SharedSecret) == 0 {
		return fmt.Errorf("shared secret required for key derivation")
	}

	cipherSuite := ctx.Protocol.GetCipherSuite()

	var keySize int
	switch cipherSuite {
	case CipherSuiteAES128:
		keySize = 16
	case CipherSuiteAES192:
		keySize = 24
	case CipherSuiteAES256:
		keySize = 32
	case CipherSuite3DES:
		keySize = 24
	default:
		return fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
	}

	hashAlg := kdf.GetHashAlgorithm(keySize)

	// Derive keys from shared secret (NOT from nonce — nonce was used for mapping)
	encKey := kdf.KDF_Enc(ctx.SharedSecret, nil, keySize, hashAlg)
	macKey := kdf.KDF_MAC(ctx.SharedSecret, nil, keySize, hashAlg)

	if cipherSuite == CipherSuite3DES {
		encKey = kdf.AdjustKeyParity(encKey)
		macKey = kdf.AdjustKeyParity(macKey)
	}

	ctx.EncryptionKey = encKey
	ctx.MACKey = macKey

	logVerbose("[PACE] Derived K_enc: %X\n", encKey)
	logVerbose("[PACE] Derived K_mac: %X\n", macKey)

	return nil
}

// PACE_STEP3D_compute_auth_token computes the authentication token per BSI TR-03110.
//
// Per BSI TR-03110 Part 3 Section 4.4.3.3:
//   T_PCD = MAC_8(K_mac, encode_public_key(PK_PICC))
//
// The encoded public key uses an ASN.1 structure:
//
//	7F49 <len>
//	  06 <oid_len> <PACE_protocol_OID>
//	  86 <pk_len>  <uncompressed_public_key>
//
// MAC_8 = first 8 bytes of AES-CMAC
func PACE_STEP3D_compute_auth_token(ctx *PACEContext, isTerminal bool) ([]byte, error) {
	if len(ctx.MACKey) == 0 {
		return nil, fmt.Errorf("MAC key required for authentication")
	}
	if ctx.EphemeralPublicKey == nil || ctx.PeerPublicKey == nil {
		return nil, fmt.Errorf("ephemeral public keys required for authentication")
	}

	// Get the peer's public key bytes (the key we MAC over)
	var peerPKBytes []byte
	if isTerminal {
		// Terminal computes T_PCD = MAC(K_mac, encode(PK_PICC))
		peerPKBytes = getPublicKeyBytes(ctx.PeerPublicKey, ctx)
	} else {
		// Card computes T_PICC = MAC(K_mac, encode(PK_PCD))
		peerPKBytes = getPublicKeyBytes(ctx.EphemeralPublicKey, ctx)
	}
	if peerPKBytes == nil {
		return nil, fmt.Errorf("failed to serialize peer public key")
	}

	// Build the authentication data per BSI TR-03110
	oidBytes := protocolOIDToBytes(ctx.Protocol)
	authData := buildAuthTokenData(oidBytes, peerPKBytes)

	logVerbose("[PACE] Auth token input: %X\n", authData)

	// Compute AES-CMAC and truncate to 8 bytes
	fullMAC, err := crypto.CMAC(ctx.MACKey, authData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute authentication token: %w", err)
	}

	authToken := fullMAC[:8]
	ctx.AuthToken = authToken

	return authToken, nil
}

// PACE_STEP3D_verify_auth_token verifies the peer's authentication token.
//
// Per BSI TR-03110:
//   Terminal verifies: T_PICC == MAC_8(K_mac, encode_public_key(PK_PCD))
func PACE_STEP3D_verify_auth_token(ctx *PACEContext, peerAuthToken []byte, isTerminal bool) error {
	if len(ctx.MACKey) == 0 {
		return fmt.Errorf("MAC key required for authentication")
	}
	if ctx.EphemeralPublicKey == nil || ctx.PeerPublicKey == nil {
		return fmt.Errorf("ephemeral public keys required for authentication")
	}

	// Get our own public key bytes (card verifies MAC over our key)
	var ownPKBytes []byte
	if isTerminal {
		// Terminal verifies T_PICC = MAC(K_mac, encode(PK_PCD))
		ownPKBytes = getPublicKeyBytes(ctx.EphemeralPublicKey, ctx)
	} else {
		// Card verifies T_PCD = MAC(K_mac, encode(PK_PICC))
		ownPKBytes = getPublicKeyBytes(ctx.PeerPublicKey, ctx)
	}
	if ownPKBytes == nil {
		return fmt.Errorf("failed to serialize own public key")
	}

	// Build expected authentication data
	oidBytes := protocolOIDToBytes(ctx.Protocol)
	authData := buildAuthTokenData(oidBytes, ownPKBytes)

	logVerbose("[PACE] Verify auth token input: %X\n", authData)

	expectedMAC, err := crypto.CMAC(ctx.MACKey, authData)
	if err != nil {
		return fmt.Errorf("failed to compute expected authentication token: %w", err)
	}
	expectedToken := expectedMAC[:8]

	logVerbose("[PACE] Expected token: %X, received: %X\n", expectedToken, peerAuthToken)

	if len(peerAuthToken) < 8 {
		return fmt.Errorf("authentication token too short: %d bytes", len(peerAuthToken))
	}

	if subtle.ConstantTimeCompare(peerAuthToken[:8], expectedToken) != 1 {
		return fmt.Errorf("authentication token verification failed")
	}

	ctx.PeerAuthToken = peerAuthToken
	return nil
}

// buildAuthTokenData builds the BSI TR-03110 authentication data structure:
//
//	7F49 <len>
//	  06 <oid_len> <oid_bytes>
//	  86 <pk_len>  <public_key_bytes>
func buildAuthTokenData(oidBytes []byte, publicKeyBytes []byte) []byte {
	oidTLV := append([]byte{0x06, byte(len(oidBytes))}, oidBytes...)
	pkTLV := buildBERTLV(0x86, publicKeyBytes)
	inner := append(oidTLV, pkTLV...)

	// 7F49 is a two-byte tag
	result := []byte{0x7F, 0x49}
	if len(inner) < 0x80 {
		result = append(result, byte(len(inner)))
	} else {
		result = append(result, 0x81, byte(len(inner)))
	}
	result = append(result, inner...)

	return result
}

// buildBERTLV creates a BER-TLV with proper length encoding.
func buildBERTLV(tag byte, value []byte) []byte {
	result := []byte{tag}
	vLen := len(value)
	if vLen < 0x80 {
		result = append(result, byte(vLen))
	} else if vLen <= 0xFF {
		result = append(result, 0x81, byte(vLen))
	} else {
		result = append(result, 0x82, byte(vLen>>8), byte(vLen))
	}
	return append(result, value...)
}

// getPublicKeyBytes extracts raw bytes from a public key stored in the context.
// Handles both []byte (brainpool) and *ecdh.PublicKey (standard curves).
func getPublicKeyBytes(pk interface{}, ctx *PACEContext) []byte {
	switch v := pk.(type) {
	case []byte:
		return v
	case interface{ Bytes() []byte }:
		return v.Bytes()
	case *big.Int:
		keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
		return crypto.DHPublicKeyToBytes(v, keySize)
	default:
		return nil
	}
}

// protocolOIDToBytes converts a ProtocolOID string to DER-encoded OID bytes.
func protocolOIDToBytes(protocol ProtocolOID) []byte {
	components := protocol.ToOIDSlice()
	if len(components) < 2 {
		return nil
	}

	result := []byte{byte(components[0]*40 + components[1])}
	for i := 2; i < len(components); i++ {
		result = append(result, encodeOIDComponent(components[i])...)
	}
	return result
}

// encodeOIDComponent encodes a single OID component in base-128.
func encodeOIDComponent(value int) []byte {
	if value < 128 {
		return []byte{byte(value)}
	}
	var encoded []byte
	for value > 0 {
		encoded = append([]byte{byte(value & 0x7F)}, encoded...)
		value >>= 7
	}
	for i := 0; i < len(encoded)-1; i++ {
		encoded[i] |= 0x80
	}
	return encoded
}
