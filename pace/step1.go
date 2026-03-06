package pace

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"

	"github.com/aarepuusepp/libopenpace-go/crypto"
	"github.com/aarepuusepp/libopenpace-go/kdf"
)

// PACE_STEP1_enc_nonce implements PACE Step 1: Encrypt Nonce.
//
// In this step, the terminal generates a random nonce and encrypts it
// using a key derived from the shared secret (CAN/PIN).
//
// Process:
//  1. Generate random nonce (typically 16 bytes for AES, 8 bytes for 3DES)
//  2. Derive encryption key from secret using KDF_PI
//  3. Encrypt nonce using the derived key
//
// Parameters:
//   - ctx: PACE context (will be updated with the nonce)
//   - secret: Shared secret (CAN, PIN, etc.)
//
// Returns the encrypted nonce to send to the card.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.1
func PACE_STEP1_enc_nonce(ctx *PACEContext, secret *PACESecret) ([]byte, error) {
	cipherSuite := ctx.Protocol.GetCipherSuite()
	
	// Determine nonce size and key size based on cipher suite.
	// Per BSI TR-03110: nonce s must be at least key_length bits,
	// and must be a multiple of the cipher block size.
	var nonceSize int
	var keySize int

	switch cipherSuite {
	case CipherSuiteAES128:
		nonceSize = 16
		keySize = 16
	case CipherSuiteAES192:
		nonceSize = 16
		keySize = 24
	case CipherSuiteAES256:
		nonceSize = 32
		keySize = 32
	case CipherSuite3DES:
		nonceSize = 8
		keySize = 24
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ctx.Nonce = nonce

	hashAlg := kdf.GetHashAlgorithm(keySize)
	encKey := kdf.KDF_PI(secret.Value, nil, keySize, hashAlg)

	if cipherSuite == CipherSuite3DES {
		encKey = kdf.AdjustKeyParity(encKey)
	}

	var encryptedNonce []byte
	var err error

	switch cipherSuite {
	case CipherSuiteAES128, CipherSuiteAES192, CipherSuiteAES256:
		// Per OpenPACE: cipher_no_pad uses AES-CBC with zero IV
		zeroIV := make([]byte, aes.BlockSize)
		encryptedNonce, err = crypto.AESEncryptCBCRaw(encKey, zeroIV, nonce)
	case CipherSuite3DES:
		encryptedNonce, err = crypto.TripleDESEncryptECB(encKey, nonce)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt nonce: %w", err)
	}

	return encryptedNonce, nil
}

