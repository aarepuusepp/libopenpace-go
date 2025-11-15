package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// TripleDESEncryptCBC encrypts data using 3DES in CBC mode with PKCS#7 padding.
//
// Parameters:
//   - key: 3DES key (24 bytes for 3-key 3DES, or 16 bytes for 2-key 3DES)
//   - iv: Initialization vector (8 bytes)
//   - plaintext: Data to encrypt
//
// Returns the ciphertext.
func TripleDESEncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
	}
	
	if len(iv) != des.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", des.BlockSize, len(iv))
	}
	
	// Apply PKCS#7 padding
	padded := PKCS7Pad(plaintext, des.BlockSize)
	
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	
	return ciphertext, nil
}

// TripleDESDecryptCBC decrypts data using 3DES in CBC mode and removes PKCS#7 padding.
//
// Parameters:
//   - key: 3DES key (24 bytes for 3-key 3DES, or 16 bytes for 2-key 3DES)
//   - iv: Initialization vector (8 bytes)
//   - ciphertext: Data to decrypt
//
// Returns the plaintext.
func TripleDESDecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
	}
	
	if len(iv) != des.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", des.BlockSize, len(iv))
	}
	
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}
	
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	
	// Remove PKCS#7 padding
	unpadded, err := PKCS7Unpad(plaintext, des.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}
	
	return unpadded, nil
}

// TripleDESEncryptECB encrypts data using 3DES in ECB mode.
// Note: ECB mode is not recommended for general use, but is required for some operations.
//
// Parameters:
//   - key: 3DES key (24 bytes for 3-key 3DES, or 16 bytes for 2-key 3DES)
//   - plaintext: Data to encrypt (will be padded if needed)
//
// Returns the ciphertext.
func TripleDESEncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
	}
	
	// Apply PKCS#7 padding
	padded := PKCS7Pad(plaintext, des.BlockSize)
	
	ciphertext := make([]byte, len(padded))
	
	// ECB mode: encrypt each block independently
	for i := 0; i < len(padded); i += des.BlockSize {
		block.Encrypt(ciphertext[i:i+des.BlockSize], padded[i:i+des.BlockSize])
	}
	
	return ciphertext, nil
}

// TripleDESDecryptECB decrypts data using 3DES in ECB mode.
//
// Parameters:
//   - key: 3DES key (24 bytes for 3-key 3DES, or 16 bytes for 2-key 3DES)
//   - ciphertext: Data to decrypt (must be multiple of block size)
//
// Returns the plaintext.
func TripleDESDecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
	}
	
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}
	
	plaintext := make([]byte, len(ciphertext))
	
	// ECB mode: decrypt each block independently
	for i := 0; i < len(ciphertext); i += des.BlockSize {
		block.Decrypt(plaintext[i:i+des.BlockSize], ciphertext[i:i+des.BlockSize])
	}
	
	// Remove PKCS#7 padding
	unpadded, err := PKCS7Unpad(plaintext, des.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}
	
	return unpadded, nil
}

