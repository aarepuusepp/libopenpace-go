package pace

import (
	"fmt"
	
	"github.com/aarepuusepp/libopenpace-go/crypto"
	"github.com/aarepuusepp/libopenpace-go/kdf"
)

// PACE_STEP2_dec_nonce implements PACE Step 2: Decrypt Nonce.
//
// In this step, the terminal receives an encrypted nonce from the card
// and decrypts it using a key derived from the shared secret.
//
// Process:
//  1. Derive decryption key from secret using KDF_PI
//  2. Decrypt the received encrypted nonce
//  3. Store the decrypted nonce in the context
//
// Parameters:
//   - ctx: PACE context (will be updated with the decrypted nonce)
//   - secret: Shared secret (CAN, PIN, etc.)
//   - encryptedNonce: Encrypted nonce received from the card
//
// Returns an error if decryption fails.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.2
func PACE_STEP2_dec_nonce(ctx *PACEContext, secret *PACESecret, encryptedNonce []byte) error {
	cipherSuite := ctx.Protocol.GetCipherSuite()
	
	// Determine key size based on cipher suite
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
	
	// Derive decryption key from secret using KDF_PI
	hashAlg := kdf.GetHashAlgorithm(keySize)
	decKey := kdf.KDF_PI(secret.Value, nil, keySize, hashAlg)
	
	// Adjust parity for 3DES keys
	if cipherSuite == CipherSuite3DES {
		decKey = kdf.AdjustKeyParity(decKey)
	}
	
	// Decrypt nonce
	var nonce []byte
	var err error
	
	switch cipherSuite {
	case CipherSuiteAES128, CipherSuiteAES192, CipherSuiteAES256:
		// Use AES in ECB mode
		nonce, err = crypto.AESDecryptECB(decKey, encryptedNonce)
	case CipherSuite3DES:
		// Use 3DES in ECB mode
		nonce, err = crypto.TripleDESDecryptECB(decKey, encryptedNonce)
	}
	
	if err != nil {
		return fmt.Errorf("failed to decrypt nonce: %w", err)
	}
	
	// Validate nonce size
	expectedSize := 16 // AES
	if cipherSuite == CipherSuite3DES {
		expectedSize = 8
	}
	
	if len(nonce) != expectedSize {
		return fmt.Errorf("invalid nonce size: expected %d, got %d", expectedSize, len(nonce))
	}
	
	// Store decrypted nonce in context
	ctx.Nonce = nonce
	
	return nil
}

