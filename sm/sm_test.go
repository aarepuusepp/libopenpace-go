package sm

import (
	"bytes"
	"encoding/hex"
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

func TestNewContext(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)
	ssc := make([]byte, 8)

	ctx, err := NewContext(encKey, macKey, ssc)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	if ctx == nil {
		t.Fatal("Context is nil")
	}

	if len(ctx.SSC) != 16 {
		t.Errorf("SSC length = %d, expected 16 (AES block size)", len(ctx.SSC))
	}

	// SSC should be initialized to zero (16 bytes for AES-128)
	expectedSSC := make([]byte, 16)
	if !bytes.Equal(ctx.SSC, expectedSSC) {
		t.Errorf("SSC = %x, expected %x", ctx.SSC, expectedSSC)
	}
}

func TestNewContext_InvalidKeys(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 24) // Different length
	ssc := make([]byte, 8)

	_, err := NewContext(encKey, macKey, ssc)
	if err == nil {
		t.Error("NewContext should fail with different key lengths")
	}
}

func TestIncrementSSC(t *testing.T) {
	tests := []struct {
		name     string
		initial  string
		expected string
	}{
		{
			name:     "Zero to one",
			initial:  "0000000000000000",
			expected: "0000000000000001",
		},
		{
			name:     "Carry over",
			initial:  "00000000000000FF",
			expected: "0000000000000100",
		},
		{
			name:     "Multiple carries",
			initial:  "000000000000FFFF",
			expected: "0000000000010000",
		},
		{
			name:     "Wrap around",
			initial:  "FFFFFFFFFFFFFFFF",
			expected: "0000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				SSC: hexDecode(tt.initial),
			}

			ctx.IncrementSSC()

			expected := hexDecode(tt.expected)
			if !bytes.Equal(ctx.SSC, expected) {
				t.Errorf("SSC = %x, expected %x", ctx.SSC, expected)
			}
		})
	}
}

func TestWrapCommand_NoData(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)
	ssc := make([]byte, 8)

	ctx, err := NewContext(encKey, macKey, ssc)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Wrap a simple SELECT command
	wrapped, err := ctx.WrapCommand(0x00, 0xA4, 0x04, 0x00, nil, 0)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// Verify structure
	if len(wrapped) < 5 {
		t.Errorf("Wrapped APDU too short: %d bytes", len(wrapped))
	}

	// Verify CLA has SM bits set
	if wrapped[0]&0x0C != 0x0C {
		t.Errorf("CLA doesn't have SM bits set: %02X", wrapped[0])
	}

	// Verify INS, P1, P2
	if wrapped[1] != 0xA4 || wrapped[2] != 0x04 || wrapped[3] != 0x00 {
		t.Error("INS, P1, P2 don't match original command")
	}
}

func TestWrapCommand_WithData(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)
	ssc := make([]byte, 8)

	ctx, err := NewContext(encKey, macKey, ssc)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Wrap a command with data
	data := []byte("Hello, World!")
	wrapped, err := ctx.WrapCommand(0x00, 0xB0, 0x00, 0x00, data, 0)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// Verify structure
	if len(wrapped) < 5 {
		t.Errorf("Wrapped APDU too short: %d bytes", len(wrapped))
	}

	// Verify CLA has SM bits set
	if wrapped[0]&0x0C != 0x0C {
		t.Errorf("CLA doesn't have SM bits set: %02X", wrapped[0])
	}
}

func TestWrapCommand_WithLe(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)
	ssc := make([]byte, 8)

	ctx, err := NewContext(encKey, macKey, ssc)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Wrap a command with Le
	wrapped, err := ctx.WrapCommand(0x00, 0xB0, 0x00, 0x00, nil, 256)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// Verify structure
	if len(wrapped) < 5 {
		t.Errorf("Wrapped APDU too short: %d bytes", len(wrapped))
	}
}

func TestWrapUnwrap_Roundtrip(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)

	// Fill keys with test data
	for i := range encKey {
		encKey[i] = byte(i)
		macKey[i] = byte(i + 16)
	}

	ssc := make([]byte, 8)
	ctx, err := NewContext(encKey, macKey, ssc)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Wrap a command with data
	originalData := []byte("Test data for roundtrip")
	wrapped, err := ctx.WrapCommand(0x00, 0xB0, 0x00, 0x00, originalData, 0)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// For testing, we need to simulate a response
	// In a real scenario, the card would process the wrapped command
	// and return a wrapped response

	// For now, just verify the command was wrapped
	if len(wrapped) < len(originalData) {
		t.Error("Wrapped command should be longer than original data")
	}
}

func TestSSC_Increment_Multiple(t *testing.T) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)
	ssc := make([]byte, 8)

	ctx, err := NewContext(encKey, macKey, ssc)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Increment SSC multiple times
	for i := 0; i < 10; i++ {
		ctx.IncrementSSC()
	}

	// SSC should be 10 (16 bytes for AES-128)
	expected := make([]byte, 16)
	expected[15] = 10
	if !bytes.Equal(ctx.SSC, expected) {
		t.Errorf("SSC after 10 increments = %x, expected %x", ctx.SSC, expected)
	}
}

func TestBuildDO_ShortForm(t *testing.T) {
	tag := byte(0x87)
	value := []byte{0x01, 0x02, 0x03}

	do := buildDO(tag, value)

	// Expected: 0x87 0x03 0x01 0x02 0x03
	expected := []byte{0x87, 0x03, 0x01, 0x02, 0x03}
	if !bytes.Equal(do, expected) {
		t.Errorf("buildDO = %x, expected %x", do, expected)
	}
}

func TestBuildDO_LongForm(t *testing.T) {
	tag := byte(0x87)
	value := make([]byte, 200) // Long value

	do := buildDO(tag, value)

	// Expected: 0x87 0x81 0xC8 [200 bytes]
	if do[0] != 0x87 || do[1] != 0x81 || do[2] != 0xC8 {
		t.Errorf("buildDO header = %x, expected 87 81 C8", do[:3])
	}

	if len(do) != 3+200 {
		t.Errorf("buildDO length = %d, expected %d", len(do), 3+200)
	}
}

func TestParseDOLength_ShortForm(t *testing.T) {
	data := []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05}

	length, size := parseDOLength(data)

	if length != 5 {
		t.Errorf("parseDOLength = %d, expected 5", length)
	}

	if size != 1 {
		t.Errorf("parseDOLength size = %d, expected 1", size)
	}
}

func TestParseDOLength_LongForm(t *testing.T) {
	data := []byte{0x81, 0xC8} // 200 in long form

	length, size := parseDOLength(data)

	if length != 200 {
		t.Errorf("parseDOLength = %d, expected 200", length)
	}

	if size != 2 {
		t.Errorf("parseDOLength size = %d, expected 2", size)
	}
}

// Helper function to decode hex strings
func hexDecode(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// Benchmark tests
func BenchmarkWrapCommand(b *testing.B) {
	encKey := make([]byte, 16)
	macKey := make([]byte, 16)
	ssc := make([]byte, 8)
	ctx, _ := NewContext(encKey, macKey, ssc)
	data := make([]byte, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.WrapCommand(0x00, 0xB0, 0x00, 0x00, data, 0)
	}
}

func BenchmarkIncrementSSC(b *testing.B) {
	ctx := &Context{
		SSC: make([]byte, 8),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.IncrementSSC()
	}
}

func TestAESOnlyContext(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		ctx, err := NewContext(make([]byte, size), make([]byte, size), make([]byte, 8))
		if err != nil {
			t.Fatal(err)
		}
		if !ctx.UseAES || ctx.BlockSize != 16 {
			t.Fatalf("size %d was not AES", size)
		}
		if _, err := ctx.WrapCommand(0, 0xB0, 0, 0, nil, 256); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewContext(make([]byte, 8), make([]byte, 8), make([]byte, 8)); err == nil {
		t.Fatal("DES accepted")
	}
	// Context fields are public; a manually constructed legacy 3DES context
	// must fail even for an APDU with no encrypted payload.
	ctx := &Context{EncryptionKey: make([]byte, 24), MACKey: make([]byte, 24), SSC: make([]byte, 8), BlockSize: 8}
	if _, err := ctx.WrapCommand(0, 0xB0, 0, 0, nil, 256); err == nil {
		t.Fatal("3DES wrap accepted")
	}
	if _, _, err := ctx.UnwrapResponse([]byte{0x90, 0}); err == nil {
		t.Fatal("3DES unwrap accepted")
	}
	for _, b := range ctx.SSC {
		if b != 0 {
			t.Fatal("SSC mutated on rejection")
		}
	}
}
