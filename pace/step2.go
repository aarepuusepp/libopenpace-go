package pace

import (
	"crypto/aes"
	"fmt"

	"github.com/aarepuusepp/libopenpace-go/crypto"
	"github.com/aarepuusepp/libopenpace-go/kdf"
)

// PACE_STEP2_dec_nonce implements PACE Step 2: Decrypt Nonce.
//
// The terminal receives an encrypted nonce from the card and decrypts it
// using a key derived from the shared secret (CAN/PIN) via KDF_PI.
//
// Per BSI TR-03110 and the OpenPACE reference implementation (cipher_no_pad),
// the cipher mode is AES-CBC with a zero IV, NOT AES-ECB. For a single-block
// nonce (16 bytes), CBC with zero IV equals ECB. However, for AES-256 PACE,
// cards (e.g. IDEMIA) send a 32-byte nonce (key-length per BSI TR-03110
// Section A.3.4), requiring correct CBC chaining across two blocks.
//
// The full decrypted output is used as the nonce — no truncation.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.2, OpenPACE pace.c
func PACE_STEP2_dec_nonce(ctx *PACEContext, secret *PACESecret, encryptedNonce []byte) error {
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
	decKey := kdf.KDF_PI(secret.Value, nil, keySize, hashAlg)

	if cipherSuite == CipherSuite3DES {
		decKey = kdf.AdjustKeyParity(decKey)
	}

	logVerbose("[PACE] Step 2 - Derived K_pi (%d bytes): %X\n", len(decKey), decKey)
	logVerbose("[PACE] Step 2 - Encrypted nonce (%d bytes): %X\n", len(encryptedNonce), encryptedNonce)

	var nonce []byte
	var err error

	switch cipherSuite {
	case CipherSuiteAES128, CipherSuiteAES192, CipherSuiteAES256:
		// Per OpenPACE: cipher_no_pad uses AES-CBC with zero IV (ctx->iv is NULL).
		// For multi-block nonces (e.g. 32 bytes for AES-256), CBC chaining is required.
		zeroIV := make([]byte, aes.BlockSize)
		nonce, err = crypto.AESDecryptCBCRaw(decKey, zeroIV, encryptedNonce)
	case CipherSuite3DES:
		nonce, err = crypto.TripleDESDecryptECB(decKey, encryptedNonce)
	}

	if err != nil {
		return fmt.Errorf("failed to decrypt nonce: %w", err)
	}

	logVerbose("[PACE] Step 2 - Decrypted nonce (%d bytes): %X\n", len(nonce), nonce)

	ctx.Nonce = nonce
	return nil
}

