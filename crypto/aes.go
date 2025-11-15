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

// AESDecryptECB decrypts data using AES in ECB mode.
//
// Parameters:
//   - key: AES key (16, 24, or 32 bytes)
//   - ciphertext: Data to decrypt (must be multiple of block size)
//
// Returns the plaintext.
func AESDecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}
	
	plaintext := make([]byte, len(ciphertext))
	
	// ECB mode: decrypt each block independently
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	
	// Remove PKCS#7 padding
	unpadded, err := PKCS7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}
	
	return unpadded, nil
}

