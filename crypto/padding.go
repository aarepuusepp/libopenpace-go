package crypto

import (
	"bytes"
	"fmt"
)

// PKCS7Pad applies PKCS#7 padding to data.
// The padding value is equal to the number of padding bytes.
//
// For example, if 3 bytes of padding are needed, the padding is: 03 03 03
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7Unpad removes PKCS#7 padding from data.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	
	if length%blockSize != 0 {
		return nil, fmt.Errorf("data length is not a multiple of block size")
	}
	
	// Get padding length from last byte
	padding := int(data[length-1])
	
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding size: %d", padding)
	}
	
	if padding > length {
		return nil, fmt.Errorf("padding size %d exceeds data length %d", padding, length)
	}
	
	// Verify all padding bytes are correct
	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding at position %d", length-1-i)
		}
	}
	
	return data[:length-padding], nil
}

// ISO9797Method2Pad applies ISO 9797-1 Method 2 padding.
// This adds a single 0x80 byte followed by zero or more 0x00 bytes.
//
// This padding method is used in some smart card operations.
func ISO9797Method2Pad(data []byte, blockSize int) []byte {
	// Add 0x80 byte
	padded := append(data, 0x80)
	
	// Add 0x00 bytes until we reach a multiple of blockSize
	padding := blockSize - (len(padded) % blockSize)
	if padding < blockSize {
		padded = append(padded, bytes.Repeat([]byte{0x00}, padding)...)
	}
	
	return padded
}

// ISO9797Method2Unpad removes ISO 9797-1 Method 2 padding.
func ISO9797Method2Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	
	// Find the 0x80 byte from the end
	i := len(data) - 1
	for i >= 0 && data[i] == 0x00 {
		i--
	}
	
	if i < 0 || data[i] != 0x80 {
		return nil, fmt.Errorf("invalid ISO 9797-1 Method 2 padding")
	}
	
	return data[:i], nil
}

// ZeroPad pads data with zero bytes to reach the specified block size.
// This is a simple padding method used in some contexts.
func ZeroPad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == blockSize {
		return data
	}
	return append(data, bytes.Repeat([]byte{0x00}, padding)...)
}

// ZeroUnpad removes trailing zero bytes from data.
// Note: This can be ambiguous if the original data ends with zeros.
func ZeroUnpad(data []byte) []byte {
	i := len(data) - 1
	for i >= 0 && data[i] == 0x00 {
		i--
	}
	return data[:i+1]
}

