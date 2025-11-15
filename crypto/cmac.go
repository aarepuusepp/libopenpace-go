package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// CMAC computes the CMAC (Cipher-based Message Authentication Code) for the given data.
// This implementation follows NIST SP 800-38B.
//
// Parameters:
//   - key: Cipher key (16, 24, or 32 bytes for AES; 8 or 24 bytes for 3DES)
//   - data: Data to authenticate
//
// Returns the CMAC value (same length as block size).
func CMAC(key, data []byte) ([]byte, error) {
	// Determine cipher type based on key length
	switch len(key) {
	case 16, 32:
		// AES-128, AES-256
		return cmacAES(key, data)
	case 24:
		// AES-192 or 3DES - default to AES
		return cmacAES(key, data)
	case 8:
		// Single DES
		return cmac3DES(key, data)
	default:
		return nil, fmt.Errorf("unsupported key length: %d", len(key))
	}
}

// cmacAES computes CMAC using AES.
func cmacAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	return cmacGeneric(block, data)
}

// cmac3DES computes CMAC using 3DES.
func cmac3DES(key, data []byte) ([]byte, error) {
	var block cipher.Block
	var err error
	
	if len(key) == 8 {
		// Single DES
		block, err = des.NewCipher(key)
	} else {
		// Triple DES
		block, err = des.NewTripleDESCipher(key)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %w", err)
	}
	
	return cmacGeneric(block, data)
}

// cmacGeneric implements the generic CMAC algorithm for any block cipher.
// This follows NIST SP 800-38B.
func cmacGeneric(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	
	// Generate subkeys K1 and K2
	k1, k2 := generateSubkeys(block)
	
	// Determine number of blocks
	n := (len(data) + blockSize - 1) / blockSize
	if n == 0 {
		n = 1
	}
	
	// Prepare last block
	lastBlock := make([]byte, blockSize)
	lastBlockComplete := len(data) > 0 && len(data)%blockSize == 0
	
	if lastBlockComplete {
		// Last block is complete: XOR with K1
		copy(lastBlock, data[len(data)-blockSize:])
		xor(lastBlock, k1)
	} else {
		// Last block is incomplete: pad and XOR with K2
		if len(data) > 0 {
			lastBlockStart := (n - 1) * blockSize
			copy(lastBlock, data[lastBlockStart:])
		}
		// Apply padding (0x80 followed by zeros)
		lastBlock[len(data)%blockSize] = 0x80
		xor(lastBlock, k2)
	}
	
	// Process all blocks except the last
	mac := make([]byte, blockSize)
	numFullBlocks := n - 1
	
	for i := 0; i < numFullBlocks; i++ {
		xor(mac, data[i*blockSize:(i+1)*blockSize])
		block.Encrypt(mac, mac)
	}
	
	// Process last block
	xor(mac, lastBlock)
	block.Encrypt(mac, mac)
	
	return mac, nil
}

// generateSubkeys generates the K1 and K2 subkeys for CMAC.
// This follows the algorithm in NIST SP 800-38B.
func generateSubkeys(block cipher.Block) (k1, k2 []byte) {
	blockSize := block.BlockSize()
	
	// L = E(K, 0^blockSize)
	l := make([]byte, blockSize)
	block.Encrypt(l, l)
	
	// K1 = L << 1
	k1 = leftShift(l)
	
	// If MSB(L) = 1, XOR K1 with Rb
	if l[0]&0x80 != 0 {
		rb := getRb(blockSize)
		xor(k1, rb)
	}
	
	// K2 = K1 << 1
	k2 = leftShift(k1)
	
	// If MSB(K1) = 1, XOR K2 with Rb
	if k1[0]&0x80 != 0 {
		rb := getRb(blockSize)
		xor(k2, rb)
	}
	
	return k1, k2
}

// leftShift performs a left shift by 1 bit on the byte array.
func leftShift(data []byte) []byte {
	result := make([]byte, len(data))
	overflow := byte(0)
	
	for i := len(data) - 1; i >= 0; i-- {
		result[i] = (data[i] << 1) | overflow
		overflow = data[i] >> 7
	}
	
	return result
}

// getRb returns the Rb constant for CMAC based on block size.
// For 128-bit blocks (AES): Rb = 0x87
// For 64-bit blocks (DES): Rb = 0x1B
func getRb(blockSize int) []byte {
	rb := make([]byte, blockSize)
	if blockSize == 16 {
		// AES: 0x87
		rb[blockSize-1] = 0x87
	} else if blockSize == 8 {
		// DES: 0x1B
		rb[blockSize-1] = 0x1B
	}
	return rb
}

// xor performs in-place XOR of dst with src.
func xor(dst, src []byte) {
	for i := range dst {
		if i < len(src) {
			dst[i] ^= src[i]
		}
	}
}

