package kdf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Expected values are fixed external fixtures, never computed by the Go KDF.
// Provenance and the independent OpenSSL verification are in testdata/README.md.
func TestReferenceVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, Operation, Secret, Nonce, Expected string
		KeyLength                                int
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 20 {
		t.Fatalf("missing reference vectors: %d", len(vectors))
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			f := KDF_PI
			switch v.Operation {
			case "enc":
				f = KDF_Enc
			case "mac":
				f = KDF_MAC
			case "pi":
			default:
				t.Fatal("unknown operation")
			}
			got := f(decode(v.Secret), decode(v.Nonce), v.KeyLength, GetHashAlgorithm(v.KeyLength))
			if !bytes.Equal(got, decode(v.Expected)) {
				t.Fatalf("got %x, want %s", got, v.Expected)
			}
		})
	}
}

func TestInvalidKDFArguments(t *testing.T) {
	for _, derive := range []func([]byte, []byte, int, HashAlgorithm) []byte{KDF_PI, KDF_Enc, KDF_MAC} {
		for _, n := range []int{-1, 0, 21, 32} {
			if got := derive([]byte("test"), nil, n, HashSHA1); got != nil {
				t.Fatalf("invalid SHA-1 length %d produced a key", n)
			}
		}
		if got := derive(nil, nil, 16, HashAlgorithm(99)); got != nil {
			t.Fatal("unknown hash accepted")
		}
	}
}

func TestGetHashAlgorithm(t *testing.T) {
	for _, tt := range []struct {
		size int
		hash HashAlgorithm
	}{
		{16, HashSHA1}, {24, HashSHA256}, {32, HashSHA256},
	} {
		if got := GetHashAlgorithm(tt.size); got != tt.hash {
			t.Errorf("size %d: got %d, want %d", tt.size, got, tt.hash)
		}
	}
}

func TestAdjustKeyParity(t *testing.T) {
	tests := []struct {
		name     string
		input    string // hex encoded
		expected string // hex encoded (with adjusted parity)
	}{
		{
			name:  "All zeros",
			input: "0000000000000000",
			// Each byte should have LSB set to make odd parity
			expected: "0101010101010101",
		},
		{
			name:  "All ones (except LSB)",
			input: "fefefefefefefefe",
			// Each byte already has odd parity (7 ones), LSB should be 0
			expected: "fefefefefefefefe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			expected, _ := hex.DecodeString(tt.expected)

			result := AdjustKeyParity(input)

			if !bytes.Equal(result, expected) {
				t.Errorf("AdjustKeyParity() = %x, expected %x", result, expected)
			}

			// Verify each byte has odd parity
			for i, b := range result {
				ones := 0
				for j := 0; j < 8; j++ {
					if (b & (1 << j)) != 0 {
						ones++
					}
				}
				if ones%2 == 0 {
					t.Errorf("Byte %d (%02x) has even parity", i, b)
				}
			}
		})
	}
}
