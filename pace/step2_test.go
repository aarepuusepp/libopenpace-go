package pace

import (
	"bytes"
	"testing"
)

func TestPACE_STEP2_dec_nonce(t *testing.T) {
	tests := []struct {
		name     string
		protocol ProtocolOID
		secret   []byte
	}{
		{
			name:     "AES-128 with CAN",
			protocol: OID_PACE_ECDH_GM_AES128,
			secret:   []byte("123456"),
		},
		{
			name:     "AES-256 with CAN",
			protocol: OID_PACE_ECDH_GM_AES256,
			secret:   []byte("123456"),
		},
		{
			name:     "3DES with CAN",
			protocol: OID_PACE_ECDH_GM_3DES,
			secret:   []byte("123456"),
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Encrypt a nonce
			ctx1 := &PACEContext{
				Protocol: tt.protocol,
			}
			
			secret := &PACESecret{
				Type:  SecretTypeCAN,
				Value: tt.secret,
			}
			
			encryptedNonce, err := PACE_STEP1_enc_nonce(ctx1, secret)
			if err != nil {
				t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
			}
			
			originalNonce := make([]byte, len(ctx1.Nonce))
			copy(originalNonce, ctx1.Nonce)
			
			// Step 2: Decrypt the nonce
			ctx2 := &PACEContext{
				Protocol: tt.protocol,
			}
			
			err = PACE_STEP2_dec_nonce(ctx2, secret, encryptedNonce)
			if err != nil {
				t.Fatalf("PACE_STEP2_dec_nonce failed: %v", err)
			}
			
			// Verify decrypted nonce matches original
			if !bytes.Equal(ctx2.Nonce, originalNonce) {
				t.Errorf("Decrypted nonce doesn't match original.\nExpected: %x\nGot: %x", originalNonce, ctx2.Nonce)
			}
		})
	}
}

func TestPACE_STEP1_STEP2_roundtrip(t *testing.T) {
	// Test that Step 1 encryption followed by Step 2 decryption recovers the original nonce
	
	protocols := []ProtocolOID{
		OID_PACE_ECDH_GM_AES128,
		OID_PACE_ECDH_GM_AES192,
		OID_PACE_ECDH_GM_AES256,
		OID_PACE_ECDH_GM_3DES,
		OID_PACE_ECDH_IM_AES128,
		OID_PACE_DH_GM_AES128,
	}
	
	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			ctx1 := &PACEContext{Protocol: protocol}
			secret := &PACESecret{Type: SecretTypeCAN, Value: []byte("123456")}
			
			// Encrypt
			encryptedNonce, err := PACE_STEP1_enc_nonce(ctx1, secret)
			if err != nil {
				t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
			}
			
			originalNonce := make([]byte, len(ctx1.Nonce))
			copy(originalNonce, ctx1.Nonce)
			
			// Decrypt
			ctx2 := &PACEContext{Protocol: protocol}
			err = PACE_STEP2_dec_nonce(ctx2, secret, encryptedNonce)
			if err != nil {
				t.Fatalf("PACE_STEP2_dec_nonce failed: %v", err)
			}
			
			// Verify
			if !bytes.Equal(ctx2.Nonce, originalNonce) {
				t.Error("Roundtrip failed: nonces don't match")
			}
		})
	}
}

func TestPACE_STEP2_wrong_secret(t *testing.T) {
	// Test that decryption with wrong secret fails or produces different nonce
	
	ctx1 := &PACEContext{Protocol: OID_PACE_ECDH_GM_AES128}
	secret1 := &PACESecret{Type: SecretTypeCAN, Value: []byte("123456")}
	
	// Encrypt with secret1
	encryptedNonce, err := PACE_STEP1_enc_nonce(ctx1, secret1)
	if err != nil {
		t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
	}
	
	originalNonce := make([]byte, len(ctx1.Nonce))
	copy(originalNonce, ctx1.Nonce)
	
	// Try to decrypt with different secret
	ctx2 := &PACEContext{Protocol: OID_PACE_ECDH_GM_AES128}
	secret2 := &PACESecret{Type: SecretTypeCAN, Value: []byte("654321")}
	
	err = PACE_STEP2_dec_nonce(ctx2, secret2, encryptedNonce)
	
	// Either decryption should fail (due to invalid padding), or
	// if it succeeds, the nonce should be different
	if err == nil {
		// Decryption succeeded, verify nonce is different
		if bytes.Equal(ctx2.Nonce, originalNonce) {
			t.Error("Decryption with wrong secret produced correct nonce (should be garbage)")
		}
	}
	// If err != nil, that's also acceptable (invalid padding from garbage data)
}

func TestPACE_STEP2_invalid_nonce_size(t *testing.T) {
	ctx := &PACEContext{Protocol: OID_PACE_ECDH_GM_AES128}
	secret := &PACESecret{Type: SecretTypeCAN, Value: []byte("123456")}
	
	// Try to decrypt invalid size encrypted nonce
	invalidEncryptedNonce := make([]byte, 8) // Wrong size for AES
	
	err := PACE_STEP2_dec_nonce(ctx, secret, invalidEncryptedNonce)
	if err == nil {
		t.Error("PACE_STEP2_dec_nonce should fail with invalid nonce size")
	}
}

