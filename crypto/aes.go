package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AESEncryptCBC encrypts data using AES in CBC mode with PKCS#7 padding.
//
// Parameters:
//   - key: AES key (16, 24, or 32 bytes for AES-128/192/256)
//   - iv: Initialization vector (16 bytes)
//   - plaintext: Data to encrypt
//
// Returns the ciphertext.
func AESEncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	
	// Apply PKCS#7 padding
	padded := PKCS7Pad(plaintext, aes.BlockSize)
	
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	
	return ciphertext, nil
}

// AESDecryptCBC decrypts data using AES in CBC mode and removes PKCS#7 padding.
//
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - iv: Initialization vector (16 bytes)
//   - ciphertext: Data to decrypt
//
// Returns the plaintext.
func AESDecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}
	
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	
	// Remove PKCS#7 padding
	unpadded, err := PKCS7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}
	
	return unpadded, nil
}

// AESEncryptECB encrypts data using AES in ECB mode.
// Note: ECB mode is not recommended for general use, but is required for some PACE operations.
//
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - plaintext: Data to encrypt (must be multiple of block size or will be padded)
//
// Returns the ciphertext.
func AESEncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	// Apply PKCS#7 padding
	padded := PKCS7Pad(plaintext, aes.BlockSize)
	
	ciphertext := make([]byte, len(padded))
	
	// ECB mode: encrypt each block independently
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	
	return ciphertext, nil
}

// AESDecryptECB decrypts data using AES in ECB mode and removes PKCS#7 padding.
//
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - ciphertext: Data to decrypt (must be multiple of block size)
//
// Returns the plaintext with PKCS#7 padding removed.
func AESDecryptECB(key, ciphertext []byte) ([]byte, error) {
	plaintext, err := AESDecryptECBRaw(key, ciphertext)
	if err != nil {
		return nil, err
	}

	unpadded, err := PKCS7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}

	return unpadded, nil
}

// AESDecryptECBRaw decrypts data using AES in ECB mode WITHOUT removing padding.
func AESDecryptECBRaw(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}

	return plaintext, nil
}

// AESEncryptCBCRaw encrypts data using AES in CBC mode WITHOUT adding padding.
// The caller must ensure plaintext is already padded to block-size multiples.
func AESEncryptCBCRaw(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size")
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AESEncryptECBBlock encrypts a single block (16 bytes) with AES-ECB.
// Used for SM IV computation: IV = AES_ECB_Enc(K_enc, SSC).
func AESEncryptECBBlock(key, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	if len(block) != aes.BlockSize {
		return nil, fmt.Errorf("block must be %d bytes, got %d", aes.BlockSize, len(block))
	}
	out := make([]byte, aes.BlockSize)
	c.Encrypt(out, block)
	return out, nil
}

// AESDecryptCBCRaw decrypts data using AES in CBC mode WITHOUT removing padding.
// Used for PACE nonce decryption per BSI TR-03110 / OpenPACE (cipher_no_pad with AES-CBC).
// For a single block with zero IV this is equivalent to ECB, but for multi-block
// ciphertexts (e.g. 32-byte nonce for AES-256) the CBC chaining is required.
func AESDecryptCBCRaw(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

