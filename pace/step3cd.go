package pace

import (
	"fmt"
	"math/big"
	
	"github.com/aarepuusepp/libopenpace-go/crypto"
	"github.com/aarepuusepp/libopenpace-go/kdf"
)

// PACE_STEP3C_derive_keys implements PACE Step 3C: Derive Session Keys.
//
// This step derives the encryption and MAC keys from the shared secret
// using the nonce as additional input.
//
// Process:
//  1. K_enc = KDF_Enc(K, nonce)
//  2. K_mac = KDF_MAC(K, nonce)
//
// Parameters:
//   - ctx: PACE context (must have shared secret and nonce)
//
// Returns an error if derivation fails.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.3
func PACE_STEP3C_derive_keys(ctx *PACEContext) error {
	if len(ctx.SharedSecret) == 0 {
		return fmt.Errorf("shared secret required for key derivation")
	}
	
	if len(ctx.Nonce) == 0 {
		return fmt.Errorf("nonce required for key derivation")
	}
	
	cipherSuite := ctx.Protocol.GetCipherSuite()
	
	// Determine key sizes based on cipher suite
	var keySize int
	
	switch cipherSuite {
	case CipherSuiteAES128:
		keySize = 16
	case CipherSuiteAES192:
		keySize = 24
	case CipherSuiteAES256:
		keySize = 32
	case CipherSuite3DES:
		keySize = 24 // 3DES uses 24-byte key (3 * 8 bytes)
	default:
		return fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
	}
	
	// Determine hash algorithm
	hashAlg := kdf.GetHashAlgorithm(keySize)
	
	// Derive encryption key
	encKey := kdf.KDF_Enc(ctx.SharedSecret, ctx.Nonce, keySize, hashAlg)
	
	// Derive MAC key
	macKey := kdf.KDF_MAC(ctx.SharedSecret, ctx.Nonce, keySize, hashAlg)
	
	// Adjust parity for 3DES keys
	if cipherSuite == CipherSuite3DES {
		encKey = kdf.AdjustKeyParity(encKey)
		macKey = kdf.AdjustKeyParity(macKey)
	}
	
	// Store keys in context
	ctx.EncryptionKey = encKey
	ctx.MACKey = macKey
	
	return nil
}

// PACE_STEP3D_mutual_authentication implements PACE Step 3D: Mutual Authentication.
//
// This step computes authentication tokens to verify that both parties
// have derived the same keys.
//
// Process:
//  1. Compute T_PCD = MAC(K_mac, PK_PCD || PK_PICC)
//  2. Compute T_PICC = MAC(K_mac, PK_PICC || PK_PCD)
//  3. Exchange and verify tokens
//
// Parameters:
//   - ctx: PACE context (must have MAC key and public keys)
//
// Returns the authentication token to send to the peer.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.3
func PACE_STEP3D_compute_auth_token(ctx *PACEContext, isTerminal bool) ([]byte, error) {
	if len(ctx.MACKey) == 0 {
		return nil, fmt.Errorf("MAC key required for authentication")
	}
	
	if ctx.EphemeralPublicKey == nil || ctx.PeerPublicKey == nil {
		return nil, fmt.Errorf("ephemeral public keys required for authentication")
	}
	
	// Serialize public keys
	var ownPK, peerPK []byte
	
	keyAgreementType := ctx.Protocol.GetKeyAgreementType()
	
	switch keyAgreementType {
	case KeyAgreementECDH:
		// For ECDH, public keys are already in byte format
		ownPKECDH, ok := ctx.EphemeralPublicKey.(interface{ Bytes() []byte })
		if !ok {
			return nil, fmt.Errorf("invalid ephemeral public key type")
		}
		ownPK = ownPKECDH.Bytes()
		
		peerPKECDH, ok := ctx.PeerPublicKey.(interface{ Bytes() []byte })
		if !ok {
			return nil, fmt.Errorf("invalid peer public key type")
		}
		peerPK = peerPKECDH.Bytes()
		
	case KeyAgreementDH:
		// For DH, convert big.Int to bytes
		ownPKInt, ok := ctx.EphemeralPublicKey.(*big.Int)
		if !ok {
			return nil, fmt.Errorf("invalid ephemeral public key type for DH")
		}
		
		peerPKInt, ok := ctx.PeerPublicKey.(*big.Int)
		if !ok {
			return nil, fmt.Errorf("invalid peer public key type for DH")
		}
		
		keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
		ownPK = crypto.DHPublicKeyToBytes(ownPKInt, keySize)
		peerPK = crypto.DHPublicKeyToBytes(peerPKInt, keySize)
	}
	
	// Compute authentication token
	var data []byte
	if isTerminal {
		// Terminal: MAC(K_mac, PK_terminal || PK_card)
		data = append(ownPK, peerPK...)
	} else {
		// Card: MAC(K_mac, PK_card || PK_terminal)
		data = append(peerPK, ownPK...)
	}
	
	// Compute MAC
	authToken, err := crypto.CMAC(ctx.MACKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to compute authentication token: %w", err)
	}
	
	// Store authentication token
	ctx.AuthToken = authToken
	
	return authToken, nil
}

// PACE_STEP3D_verify_auth_token verifies the peer's authentication token.
//
// Parameters:
//   - ctx: PACE context (must have MAC key and public keys)
//   - peerAuthToken: Authentication token received from peer
//   - isTerminal: True if we are the terminal, false if we are the card
//
// Returns an error if verification fails.
func PACE_STEP3D_verify_auth_token(ctx *PACEContext, peerAuthToken []byte, isTerminal bool) error {
	if len(ctx.MACKey) == 0 {
		return fmt.Errorf("MAC key required for authentication")
	}
	
	if ctx.EphemeralPublicKey == nil || ctx.PeerPublicKey == nil {
		return fmt.Errorf("ephemeral public keys required for authentication")
	}
	
	// Serialize public keys
	var ownPK, peerPK []byte
	
	keyAgreementType := ctx.Protocol.GetKeyAgreementType()
	
	switch keyAgreementType {
	case KeyAgreementECDH:
		ownPKECDH, ok := ctx.EphemeralPublicKey.(interface{ Bytes() []byte })
		if !ok {
			return fmt.Errorf("invalid ephemeral public key type")
		}
		ownPK = ownPKECDH.Bytes()
		
		peerPKECDH, ok := ctx.PeerPublicKey.(interface{ Bytes() []byte })
		if !ok {
			return fmt.Errorf("invalid peer public key type")
		}
		peerPK = peerPKECDH.Bytes()
		
	case KeyAgreementDH:
		ownPKInt, ok := ctx.EphemeralPublicKey.(*big.Int)
		if !ok {
			return fmt.Errorf("invalid ephemeral public key type for DH")
		}
		
		peerPKInt, ok := ctx.PeerPublicKey.(*big.Int)
		if !ok {
			return fmt.Errorf("invalid peer public key type for DH")
		}
		
		keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
		ownPK = crypto.DHPublicKeyToBytes(ownPKInt, keySize)
		peerPK = crypto.DHPublicKeyToBytes(peerPKInt, keySize)
	}
	
	// Compute expected authentication token
	var data []byte
	if isTerminal {
		// We are terminal, peer is card: MAC(K_mac, PK_card || PK_terminal)
		data = append(peerPK, ownPK...)
	} else {
		// We are card, peer is terminal: MAC(K_mac, PK_terminal || PK_card)
		data = append(ownPK, peerPK...)
	}
	
	// Compute expected MAC
	expectedToken, err := crypto.CMAC(ctx.MACKey, data)
	if err != nil {
		return fmt.Errorf("failed to compute expected authentication token: %w", err)
	}
	
	// Compare tokens (constant-time comparison to prevent timing attacks)
	if len(peerAuthToken) != len(expectedToken) {
		return fmt.Errorf("authentication token length mismatch")
	}
	
	match := byte(0)
	for i := range expectedToken {
		match |= peerAuthToken[i] ^ expectedToken[i]
	}
	
	if match != 0 {
		return fmt.Errorf("authentication token verification failed")
	}
	
	// Store peer's authentication token
	ctx.PeerAuthToken = peerAuthToken
	
	return nil
}

