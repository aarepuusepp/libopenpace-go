package pace

import (
	"testing"
)

func TestSetVerbose(t *testing.T) {
	SetVerbose(true)
	if !verboseMode {
		t.Error("SetVerbose(true) did not enable verbose mode")
	}

	SetVerbose(false)
	if verboseMode {
		t.Error("SetVerbose(false) did not disable verbose mode")
	}
}

func TestPACE_STEP1_enc_nonce(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &PACEContext{
				Protocol: tt.protocol,
			}

			secret := &PACESecret{
				Type:  SecretTypeCAN,
				Value: tt.secret,
			}

			encryptedNonce, err := PACE_STEP1_enc_nonce(ctx, secret)
			if err != nil {
				t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
			}

			// Verify nonce was stored in context
			if len(ctx.Nonce) == 0 {
				t.Error("Nonce was not stored in context")
			}

			// Verify encrypted nonce is not empty
			if len(encryptedNonce) == 0 {
				t.Error("Encrypted nonce is empty")
			}

			// Verify encrypted nonce is different from plaintext nonce
			// (this would be extremely unlikely to fail randomly)
			if string(encryptedNonce) == string(ctx.Nonce) {
				t.Error("Encrypted nonce is same as plaintext nonce")
			}
		})
	}
}

func TestPACE_STEP1_nonce_size(t *testing.T) {
	tests := []struct {
		protocol     ProtocolOID
		expectedSize int
	}{
		{OID_PACE_ECDH_GM_AES128, 16},
		{OID_PACE_ECDH_GM_AES192, 16},
		{OID_PACE_ECDH_GM_AES256, 32},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			ctx := &PACEContext{
				Protocol: tt.protocol,
			}

			secret := &PACESecret{
				Type:  SecretTypeCAN,
				Value: []byte("123456"),
			}

			_, err := PACE_STEP1_enc_nonce(ctx, secret)
			if err != nil {
				t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
			}

			if len(ctx.Nonce) != tt.expectedSize {
				t.Errorf("Nonce size = %d, expected %d", len(ctx.Nonce), tt.expectedSize)
			}
		})
	}
}

func TestPACE_STEP1_determinism(t *testing.T) {
	// Note: PACE_STEP1 should NOT be deterministic because it generates a random nonce
	// This test verifies that different calls produce different nonces

	ctx1 := &PACEContext{Protocol: OID_PACE_ECDH_GM_AES128}
	ctx2 := &PACEContext{Protocol: OID_PACE_ECDH_GM_AES128}
	secret := &PACESecret{Type: SecretTypeCAN, Value: []byte("123456")}

	enc1, err := PACE_STEP1_enc_nonce(ctx1, secret)
	if err != nil {
		t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
	}

	enc2, err := PACE_STEP1_enc_nonce(ctx2, secret)
	if err != nil {
		t.Fatalf("PACE_STEP1_enc_nonce failed: %v", err)
	}

	// Nonces should be different (random)
	if string(ctx1.Nonce) == string(ctx2.Nonce) {
		t.Error("Generated nonces are identical (should be random)")
	}

	// Encrypted nonces should also be different
	if string(enc1) == string(enc2) {
		t.Error("Encrypted nonces are identical (should be different due to random nonces)")
	}
}
