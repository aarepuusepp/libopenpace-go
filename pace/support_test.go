package pace

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

type probingCard struct {
	cardAccess []byte
	commands   [][]byte
}

func (c *probingCard) Transmit(command []byte) ([]byte, error) {
	c.commands = append(c.commands, append([]byte(nil), command...))
	if command[1] == 0xB0 {
		return append(append([]byte(nil), c.cardAccess...), 0x90, 0), nil
	}
	return []byte{0x90, 0}, nil
}
func unsupportedProtocols() []ProtocolOID {
	var result []ProtocolOID
	for mapping := 1; mapping <= 4; mapping++ {
		for cipher := 1; cipher <= 4; cipher++ {
			if mapping >= 3 || cipher == 1 {
				result = append(result, ProtocolOID(fmt.Sprintf("0.4.0.127.0.7.2.2.4.%d.%d", mapping, cipher)))
			}
		}
	}
	return append(result, "", "0.4.0.127.0.7.2.2.4.99.2")
}

func TestUnsupportedProtocolsFailBeforeCardIOOrMutation(t *testing.T) {
	for _, protocol := range unsupportedProtocols() {
		t.Run(string(protocol), func(t *testing.T) {
			ctx := &PACEContext{Protocol: protocol}
			secret := &PACESecret{Type: SecretTypeCAN, Value: []byte("123456")}
			check := func(err error) {
				t.Helper()
				if !errors.Is(err, ErrUnsupportedProtocol) {
					t.Fatalf("expected unsupported protocol, got %v", err)
				}
			}
			card := &probingCard{}
			_, err := SelectSuiteFromOID(protocol)
			check(err)
			_, err = PerformPACE(card, secret, protocol, 13)
			check(err)
			_, err = EstablishPACE(card, secret, protocol, 13)
			check(err)
			_, err = PACE_STEP1_enc_nonce(ctx, secret)
			check(err)
			check(PACE_STEP2_dec_nonce(ctx, secret, make([]byte, 16)))
			check(PACE_STEP3A_map_generator(ctx, nil))
			_, err = PACE_STEP3B_generate_ephemeral_key(ctx)
			check(err)
			check(PACE_STEP3B_compute_shared_secret(ctx, nil))
			check(PACE_STEP3C_derive_keys(ctx))
			_, err = PACE_STEP3D_compute_auth_token(ctx, true)
			check(err)
			check(PACE_STEP3D_verify_auth_token(ctx, nil, true))
			if len(card.commands) != 0 {
				t.Fatal("card IO occurred for unsupported caller OID")
			}
			if ctx.Nonce != nil || ctx.MappedGenerator != nil || ctx.EncryptionKey != nil || ctx.AuthToken != nil {
				t.Fatal("context mutated")
			}
		})
	}
}

func TestCardAccessCannotEnableUnsupportedProtocol(t *testing.T) {
	for _, protocol := range unsupportedProtocols() {
		if protocol == "" {
			continue
		}
		t.Run(string(protocol), func(t *testing.T) {
			oid := protocolOIDToBytes(protocol)
			info := append([]byte{0x06, byte(len(oid))}, oid...)
			info = append(info, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0D)
			data := append([]byte{0x31, byte(len(info) + 2), 0x30, byte(len(info))}, info...)
			card := &probingCard{cardAccess: data}
			_, err := PerformPACE(card, &PACESecret{Type: SecretTypeCAN, Value: []byte("123456")}, OID_PACE_ECDH_GM_AES256, 13)
			if !errors.Is(err, ErrUnsupportedProtocol) {
				t.Fatalf("got %v", err)
			}
			for _, cmd := range card.commands {
				if cmd[1] == 0x22 || cmd[1] == 0x86 {
					t.Fatalf("MSE/GA sent for unsupported CardAccess: %x", cmd)
				}
			}
		})
	}
}

func TestEnabledAESProtocols(t *testing.T) {
	for _, p := range []ProtocolOID{OID_PACE_ECDH_GM_AES128, OID_PACE_ECDH_GM_AES192, OID_PACE_ECDH_GM_AES256,
		OID_PACE_DH_GM_AES128, OID_PACE_DH_GM_AES192, OID_PACE_DH_GM_AES256} {
		if err := ValidateProtocol(p); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenPACEWorkedExampleAES128(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// OpenPACE eactest.c ECDH worked example, pinned in kdf/testdata/README.md.
	ctx := &PACEContext{Protocol: OID_PACE_ECDH_GM_AES128}
	if err := PACE_STEP2_dec_nonce(ctx, &PACESecret{Type: SecretTypePIN, Value: []byte("123456")},
		decode("ce834cde69ffbb1d1eb21585cd709f18")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Nonce, decode("7d98c00fc6c9e9543bbf94a87073a123")) {
		t.Fatalf("nonce %x", ctx.Nonce)
	}
	ctx.SharedSecret = decode("6e7d077ccd367c2eaa683f1e8ec534302e2d00b6adaf8a87a6eda78740f17606")
	if err := PACE_STEP3C_derive_keys(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.EncryptionKey, decode("68406b4162100563d9c901a6154d2901")) {
		t.Fatalf("K_enc %x", ctx.EncryptionKey)
	}
	if !bytes.Equal(ctx.MACKey, decode("73ff268784f72af833fdc9464049afc9")) {
		t.Fatalf("K_mac %x", ctx.MACKey)
	}
}
