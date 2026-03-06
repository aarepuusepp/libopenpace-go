package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

// Test AES encryption/decryption
func TestAESEncryptDecryptCBC(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes for AES-128
	iv := []byte("fedcba9876543210")  // 16 bytes
	plaintext := []byte("Hello, World! This is a test message.")
	
	ciphertext, err := AESEncryptCBC(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESEncryptCBC failed: %v", err)
	}
	
	decrypted, err := AESDecryptCBC(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESDecryptCBC failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestAESEncryptDecryptECB(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("Hello, World!")
	
	ciphertext, err := AESEncryptECB(key, plaintext)
	if err != nil {
		t.Fatalf("AESEncryptECB failed: %v", err)
	}
	
	decrypted, err := AESDecryptECB(key, ciphertext)
	if err != nil {
		t.Fatalf("AESDecryptECB failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

// Test 3DES encryption/decryption
func TestTripleDESEncryptDecryptCBC(t *testing.T) {
	key := []byte("0123456789abcdef01234567") // 24 bytes for 3DES
	iv := []byte("fedcba98")                   // 8 bytes
	plaintext := []byte("Hello, World! This is a test.")
	
	ciphertext, err := TripleDESEncryptCBC(key, iv, plaintext)
	if err != nil {
		t.Fatalf("TripleDESEncryptCBC failed: %v", err)
	}
	
	decrypted, err := TripleDESDecryptCBC(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("TripleDESDecryptCBC failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

// Test padding
func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		blockSize int
		expected  string
	}{
		{"1 byte padding", "0123456789abcde", 16, "0123456789abcde\x01"},
		{"2 bytes padding", "0123456789abcd", 16, "0123456789abcd\x02\x02"},
		{"Full block padding", "0123456789abcdef", 16, "0123456789abcdef\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := PKCS7Pad([]byte(tt.data), tt.blockSize)
			if string(padded) != tt.expected {
				t.Errorf("PKCS7Pad() = %q, expected %q", padded, tt.expected)
			}
			
			unpadded, err := PKCS7Unpad(padded, tt.blockSize)
			if err != nil {
				t.Errorf("PKCS7Unpad() error: %v", err)
			}
			
			if string(unpadded) != tt.data {
				t.Errorf("PKCS7Unpad() = %q, expected %q", unpadded, tt.data)
			}
		})
	}
}

func TestISO9797Method2Padding(t *testing.T) {
	data := []byte("Hello")
	blockSize := 8
	
	padded := ISO9797Method2Pad(data, blockSize)
	
	// Should be: "Hello" + 0x80 + 0x00 0x00
	expected := []byte{'H', 'e', 'l', 'l', 'o', 0x80, 0x00, 0x00}
	if !bytes.Equal(padded, expected) {
		t.Errorf("ISO9797Method2Pad() = %x, expected %x", padded, expected)
	}
	
	unpadded, err := ISO9797Method2Unpad(padded)
	if err != nil {
		t.Errorf("ISO9797Method2Unpad() error: %v", err)
	}
	
	if !bytes.Equal(unpadded, data) {
		t.Errorf("ISO9797Method2Unpad() = %x, expected %x", unpadded, data)
	}
}

func TestAESEncryptDecryptCBCRaw(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := make([]byte, 16)
	plaintext := []byte("0123456789abcdef") // exactly 1 block, no padding needed

	ciphertext, err := AESEncryptCBCRaw(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESEncryptCBCRaw failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := AESDecryptCBCRaw(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESDecryptCBCRaw failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("roundtrip failed: got %x, want %x", decrypted, plaintext)
	}
}

func TestAESEncryptDecryptCBCRaw_MultiBlock(t *testing.T) {
	key := make([]byte, 32) // AES-256
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, 16)
	plaintext := make([]byte, 32) // 2 blocks
	for i := range plaintext {
		plaintext[i] = byte(i + 0x10)
	}

	ciphertext, err := AESEncryptCBCRaw(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESEncryptCBCRaw failed: %v", err)
	}

	decrypted, err := AESDecryptCBCRaw(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESDecryptCBCRaw failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("multi-block roundtrip failed: got %x, want %x", decrypted, plaintext)
	}
}

func TestAESDecryptECBRaw(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("0123456789abcdef") // exactly 1 block

	ciphertext, err := AESEncryptECB(key, plaintext)
	if err != nil {
		t.Fatalf("AESEncryptECB failed: %v", err)
	}

	// AESDecryptECBRaw should return the original data without unpadding
	decrypted, err := AESDecryptECBRaw(key, ciphertext[:16])
	if err != nil {
		t.Fatalf("AESDecryptECBRaw failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("AESDecryptECBRaw got %x, want %x", decrypted, plaintext)
	}
}

func TestAESEncryptECBBlock(t *testing.T) {
	key := []byte("0123456789abcdef")
	block := make([]byte, 16)
	for i := range block {
		block[i] = byte(i)
	}

	encrypted, err := AESEncryptECBBlock(key, block)
	if err != nil {
		t.Fatalf("AESEncryptECBBlock failed: %v", err)
	}

	if len(encrypted) != 16 {
		t.Errorf("AESEncryptECBBlock output length = %d, expected 16", len(encrypted))
	}

	if bytes.Equal(encrypted, block) {
		t.Error("encrypted block should differ from input")
	}

	// Verify via ECBRaw decrypt
	decrypted, err := AESDecryptECBRaw(key, encrypted)
	if err != nil {
		t.Fatalf("AESDecryptECBRaw failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Errorf("roundtrip mismatch: got %x, want %x", decrypted, block)
	}
}

func TestAESEncryptECBBlock_WrongSize(t *testing.T) {
	key := []byte("0123456789abcdef")
	shortBlock := []byte{0x01, 0x02, 0x03}

	_, err := AESEncryptECBBlock(key, shortBlock)
	if err == nil {
		t.Error("AESEncryptECBBlock should reject non-block-size input")
	}
}

func TestAESCBCRaw_InvalidInput(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := make([]byte, 16)

	// Non-block-aligned plaintext
	_, err := AESEncryptCBCRaw(key, iv, []byte("short"))
	if err == nil {
		t.Error("AESEncryptCBCRaw should reject non-block-aligned plaintext")
	}

	// Wrong IV size
	_, err = AESEncryptCBCRaw(key, []byte("short"), make([]byte, 16))
	if err == nil {
		t.Error("AESEncryptCBCRaw should reject wrong IV size")
	}

	// Non-block-aligned ciphertext
	_, err = AESDecryptCBCRaw(key, iv, []byte("short"))
	if err == nil {
		t.Error("AESDecryptCBCRaw should reject non-block-aligned ciphertext")
	}
}

// Test CMAC
func TestCMAC_AES(t *testing.T) {
	// Test vector from NIST SP 800-38B
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	data, _ := hex.DecodeString("")
	
	mac, err := CMAC(key, data)
	if err != nil {
		t.Fatalf("CMAC failed: %v", err)
	}
	
	// Expected CMAC for empty message with this key
	expected, _ := hex.DecodeString("bb1d6929e95937287fa37d129b756746")
	if !bytes.Equal(mac, expected) {
		t.Errorf("CMAC() = %x, expected %x", mac, expected)
	}
}

func TestCMAC_Determinism(t *testing.T) {
	key := []byte("0123456789abcdef")
	data := []byte("Test message for CMAC")
	
	mac1, err := CMAC(key, data)
	if err != nil {
		t.Fatalf("CMAC failed: %v", err)
	}
	
	mac2, err := CMAC(key, data)
	if err != nil {
		t.Fatalf("CMAC failed: %v", err)
	}
	
	if !bytes.Equal(mac1, mac2) {
		t.Error("CMAC is not deterministic")
	}
}

// Test ECDH
func TestECDH(t *testing.T) {
	curve := ecdh.P256()
	
	// Generate two keypairs
	priv1, pub1, err := ECDHGenerateKey(curve)
	if err != nil {
		t.Fatalf("ECDHGenerateKey failed: %v", err)
	}
	
	priv2, pub2, err := ECDHGenerateKey(curve)
	if err != nil {
		t.Fatalf("ECDHGenerateKey failed: %v", err)
	}
	
	// Compute shared secrets
	secret1, err := ECDHComputeSharedSecret(priv1, pub2)
	if err != nil {
		t.Fatalf("ECDHComputeSharedSecret failed: %v", err)
	}
	
	secret2, err := ECDHComputeSharedSecret(priv2, pub1)
	if err != nil {
		t.Fatalf("ECDHComputeSharedSecret failed: %v", err)
	}
	
	// Shared secrets should be equal
	if !bytes.Equal(secret1, secret2) {
		t.Error("ECDH shared secrets don't match")
	}
}

func TestECDHPublicKeyRoundtrip(t *testing.T) {
	curve := ecdh.P256()
	
	_, pub, err := ECDHGenerateKey(curve)
	if err != nil {
		t.Fatalf("ECDHGenerateKey failed: %v", err)
	}
	
	// Convert to bytes and back
	pubBytes := pub.Bytes()
	pub2, err := ECDHPublicKeyFromBytes(curve, pubBytes)
	if err != nil {
		t.Fatalf("ECDHPublicKeyFromBytes failed: %v", err)
	}
	
	if !bytes.Equal(pub.Bytes(), pub2.Bytes()) {
		t.Error("Public key roundtrip failed")
	}
}

// Test DH
func TestDH(t *testing.T) {
	params, err := GetStandardDHParameters("modp2048")
	if err != nil {
		t.Fatalf("GetStandardDHParameters failed: %v", err)
	}
	
	// Generate two keypairs
	priv1, pub1, err := DHGenerateKey(params)
	if err != nil {
		t.Fatalf("DHGenerateKey failed: %v", err)
	}
	
	priv2, pub2, err := DHGenerateKey(params)
	if err != nil {
		t.Fatalf("DHGenerateKey failed: %v", err)
	}
	
	// Compute shared secrets
	secret1, err := DHComputeSharedSecret(params, priv1, pub2)
	if err != nil {
		t.Fatalf("DHComputeSharedSecret failed: %v", err)
	}
	
	secret2, err := DHComputeSharedSecret(params, priv2, pub1)
	if err != nil {
		t.Fatalf("DHComputeSharedSecret failed: %v", err)
	}
	
	// Shared secrets should be equal
	if secret1.Cmp(secret2) != 0 {
		t.Error("DH shared secrets don't match")
	}
}

func TestDHPublicKeyRoundtrip(t *testing.T) {
	params, _ := GetStandardDHParameters("modp2048")
	
	_, pub, err := DHGenerateKey(params)
	if err != nil {
		t.Fatalf("DHGenerateKey failed: %v", err)
	}
	
	// Convert to bytes and back
	pubBytes := DHPublicKeyToBytes(pub, 256)
	pub2 := DHPublicKeyFromBytes(pubBytes)
	
	if pub.Cmp(pub2) != 0 {
		t.Error("DH public key roundtrip failed")
	}
}

// Benchmarks
func BenchmarkAESEncryptCBC(b *testing.B) {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	plaintext := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESEncryptCBC(key, iv, plaintext)
	}
}

func BenchmarkCMAC(b *testing.B) {
	key := []byte("0123456789abcdef")
	data := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CMAC(key, data)
	}
}

func BenchmarkECDH(b *testing.B) {
	curve := ecdh.P256()
	priv1, _ := curve.GenerateKey(nil)
	_, pub2, _ := ECDHGenerateKey(curve)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ECDHComputeSharedSecret(priv1, pub2)
	}
}

