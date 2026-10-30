package sm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/aarepuusepp/libopenpace-go/crypto"
)

var verboseMode bool

// SetVerbose enables or disables verbose debug logging for Secure Messaging.
func SetVerbose(enabled bool) {
	verboseMode = enabled
}

func logVerbose(format string, args ...interface{}) {
	if verboseMode {
		fmt.Printf(format, args...)
	}
}

// Context holds the Secure Messaging session state.
type Context struct {
	EncryptionKey []byte // K_enc for encrypting command data
	MACKey        []byte // K_mac for MAC computation
	SSC           []byte // Send Sequence Counter (block-size bytes, big-endian)
	BlockSize     int    // AES block size (16)
	UseAES        bool   // Must be true; non-AES contexts are rejected
}

// NewContext creates an AES-only Secure Messaging context.
// A 24-byte key means AES-192, never 3DES.
//
// Parameters:
//   - encKey: Encryption key (16, 24, or 32 bytes for AES)
//   - macKey: MAC key (same length as encryption key)
//   - sscInitial: Initial Send Sequence Counter (8 bytes) as defined by PACE
//
// Returns a new SM context with SSC stored as block-size bytes (zero-padded on the left).
func NewContext(encKey, macKey, sscInitial []byte) (*Context, error) {
	if len(encKey) != len(macKey) {
		return nil, fmt.Errorf("encryption and MAC keys must have the same length")
	}
	if len(sscInitial) != 8 {
		return nil, fmt.Errorf("initial SSC must be 8 bytes")
	}

	const blockSize = 16
	const useAES = true
	switch len(encKey) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("only AES-128/192/256 secure messaging is supported")
	}

	// Store SSC as block-size bytes (left-padded with zeros).
	// Per OpenPACE encode_ssc: SSC is encoded as cipher block_size bytes.
	ssc := make([]byte, blockSize)
	copy(ssc[blockSize-len(sscInitial):], sscInitial)

	return &Context{
		EncryptionKey: encKey,
		MACKey:        macKey,
		SSC:           ssc,
		BlockSize:     blockSize,
		UseAES:        useAES,
	}, nil
}

// IncrementSSC increments the Send Sequence Counter.
// SSC is stored as block-size bytes in big-endian order.
func (ctx *Context) IncrementSSC() {
	for i := len(ctx.SSC) - 1; i >= 0; i-- {
		ctx.SSC[i]++
		if ctx.SSC[i] != 0 {
			break
		}
	}
}

// SetSSC sets the Send Sequence Counter to the given value.
// Accepts 8-byte or block-size byte SSC. If 8 bytes, left-pads to block size.
func (ctx *Context) SetSSC(ssc []byte) error {
	if len(ssc) == ctx.BlockSize {
		ctx.SSC = append(ctx.SSC[:0], ssc...)
		return nil
	}
	if len(ssc) == 8 {
		padded := make([]byte, ctx.BlockSize)
		copy(padded[ctx.BlockSize-8:], ssc)
		ctx.SSC = padded
		return nil
	}
	return fmt.Errorf("ssc must be 8 or %d bytes, got %d", ctx.BlockSize, len(ssc))
}

// WrapCommand wraps a command APDU with Secure Messaging per BSI TR-03110 / ISO 7816-4.
//
// Process:
//  1. Increment SSC
//  2. Encrypt command data with IV = AES_ECB(K_enc, SSC) (if present)
//  3. Build DO87 (encrypted data) and DO97 (Le)
//  4. Compute MAC: CMAC(K_mac, SSC || padded_header || DO87 || DO97)
//  5. Build DO8E (8-byte truncated MAC)
//  6. Construct protected APDU with Le'=0x00 appended
//
// Parameters:
//   - cla, ins, p1, p2: APDU header
//   - data: Command data (can be empty)
//   - le: Expected response length (0 for no Le, 256 for Le=00)
//
// Returns the wrapped APDU bytes.
func (ctx *Context) WrapCommand(cla, ins, p1, p2 byte, data []byte, le int) ([]byte, error) {
	if !ctx.UseAES || ctx.BlockSize != 16 {
		return nil, fmt.Errorf("DES/3DES secure messaging is disabled")
	}
	ctx.IncrementSSC()

	// Header with SM indicator bits set in CLA
	header := []byte{cla | 0x0C, ins, p1, p2}

	var dataObjects []byte

	// DO87: Encrypted data (if data is present)
	if len(data) > 0 {
		encryptedData, err := ctx.encryptData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}
		do87 := buildDO(0x87, append([]byte{0x01}, encryptedData...))
		dataObjects = append(dataObjects, do87...)
	}

	// DO97: Le (if present)
	if le > 0 {
		leBytes := []byte{byte(le)}
		if le == 256 {
			leBytes = []byte{0x00}
		}
		do97 := buildDO(0x97, leBytes)
		dataObjects = append(dataObjects, do97...)
	}

	// MAC input per ISO 7816-4 / BSI TR-03110:
	//   CMAC(K_mac, ISO_pad(SSC || ISO_pad(header) || DO87 || DO97))
	// The header is separately padded to block boundary.
	// Then the entire concatenation is ISO-padded so CMAC sees a complete input.
	paddedHeader := crypto.ISO9797Method2Pad(header, ctx.BlockSize)

	raw := make([]byte, 0, len(ctx.SSC)+len(paddedHeader)+len(dataObjects)+ctx.BlockSize)
	raw = append(raw, ctx.SSC...)
	raw = append(raw, paddedHeader...)
	raw = append(raw, dataObjects...)
	macInput := crypto.ISO9797Method2Pad(raw, ctx.BlockSize)

	logVerbose("[SM] WrapCommand: SSC=%X header=%X DOs_len=%d\n", ctx.SSC, header, len(dataObjects))
	logVerbose("[SM] CMAC input: %X\n", macInput)

	mac, err := crypto.CMAC(ctx.MACKey, macInput)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}

	do8E := buildDO(0x8E, mac[:8])

	// Build protected APDU: CLA' INS P1 P2 Lc' [DO87] [DO97] DO8E Le'
	lc := len(dataObjects) + len(do8E)
	protectedAPDU := make([]byte, 0, 4+1+lc+1)
	protectedAPDU = append(protectedAPDU, header...)
	protectedAPDU = append(protectedAPDU, byte(lc))
	protectedAPDU = append(protectedAPDU, dataObjects...)
	protectedAPDU = append(protectedAPDU, do8E...)
	protectedAPDU = append(protectedAPDU, 0x00) // Le' = request full response

	return protectedAPDU, nil
}

// UnwrapResponse unwraps a response APDU protected with Secure Messaging.
//
// Process:
//  1. Increment SSC
//  2. Parse data objects (DO87, DO99, DO8E)
//  3. Verify MAC
//  4. Decrypt data (if present)
//  5. Return plaintext data and status word
//
// Parameters:
//   - response: Protected response APDU
//
// Returns the plaintext data, status word (SW1SW2), and error.
//
// Reference: BSI TR-03110 Secure Messaging
func (ctx *Context) UnwrapResponse(response []byte) ([]byte, uint16, error) {
	if !ctx.UseAES || ctx.BlockSize != 16 {
		return nil, 0, fmt.Errorf("DES/3DES secure messaging is disabled")
	}
	if len(response) < 2 {
		return nil, 0, fmt.Errorf("response too short: %d bytes", len(response))
	}

	// Check if this is a plain error response (not SM-protected)
	// Plain error responses are just SW1 SW2 (2 bytes)
	if len(response) == 2 {
		sw := binary.BigEndian.Uint16(response)
		return nil, sw, nil
	}

	// Increment SSC
	ctx.IncrementSSC()

	// Parse response
	// Response format: [DO87] [DO99] DO8E SW1 SW2
	data := response[:len(response)-2]
	sw := binary.BigEndian.Uint16(response[len(response)-2:])

	// Parse data objects
	var encryptedData []byte
	var statusBytes []byte
	var mac []byte

	pos := 0
	for pos < len(data) {
		if pos+2 > len(data) {
			return nil, 0, fmt.Errorf("invalid data object at position %d", pos)
		}

		tag := data[pos]
		length, lenSize := parseDOLength(data[pos+1:])
		pos += 1 + lenSize

		if pos+length > len(data) {
			return nil, 0, fmt.Errorf("data object length exceeds response size")
		}

		value := data[pos : pos+length]
		pos += length

		switch tag {
		case 0x87: // Encrypted data
			if len(value) < 1 || value[0] != 0x01 {
				return nil, 0, fmt.Errorf("invalid DO87 format")
			}
			encryptedData = value[1:]
		case 0x99: // Status bytes
			statusBytes = value
		case 0x8E: // MAC
			mac = value
		default:
			// Unknown tag, skip
		}
	}

	if len(mac) == 0 {
		return nil, 0, fmt.Errorf("missing MAC (DO8E)")
	}

	// Verify MAC per ISO 7816-4 / BSI TR-03110:
	// MAC input = ISO_pad(SSC || data_objects_without_DO8E)
	// The DO8E itself is excluded from the MAC computation.
	// The entire input is ISO-padded before CMAC (so CMAC sees a complete input).
	do8eLen := 2 + len(mac) // tag(1) + length(1) + value
	dosWithoutMAC := data[:len(data)-do8eLen]

	raw := make([]byte, 0, len(ctx.SSC)+len(dosWithoutMAC)+ctx.BlockSize)
	raw = append(raw, ctx.SSC...)
	raw = append(raw, dosWithoutMAC...)
	macInput := crypto.ISO9797Method2Pad(raw, ctx.BlockSize)

	logVerbose("[SM] UnwrapResponse: SSC=%X data_len=%d\n", ctx.SSC, len(data))
	logVerbose("[SM] CMAC input: %X\n", macInput)
	logVerbose("[SM] Received MAC: %X\n", mac)

	expectedMAC, err := crypto.CMAC(ctx.MACKey, macInput)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute MAC: %w", err)
	}

	logVerbose("[SM] Expected MAC: %X\n", expectedMAC[:8])
	if len(mac) != 8 || !bytes.Equal(mac, expectedMAC[:8]) {
		return nil, 0, fmt.Errorf("MAC verification failed: got %X, expected %X", mac, expectedMAC[:8])
	}

	// Decrypt data (if present)
	var plaintext []byte
	if len(encryptedData) > 0 {
		plaintext, err = ctx.decryptData(encryptedData)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decrypt data: %w", err)
		}
	}

	// Use status bytes from DO99 if present, otherwise use SW from response
	if len(statusBytes) == 2 {
		sw = binary.BigEndian.Uint16(statusBytes)
	}

	return plaintext, sw, nil
}

// computeIV computes the SM encryption IV per OpenPACE update_iv:
// IV = AES_ECB_Enc(K_enc, SSC). Non-AES contexts are rejected.
func (ctx *Context) computeIV() ([]byte, error) {
	if ctx.UseAES {
		return crypto.AESEncryptECBBlock(ctx.EncryptionKey, ctx.SSC)
	}
	return nil, fmt.Errorf("DES/3DES secure messaging is disabled")
}

// encryptData encrypts data for DO87 using AES-CBC with IV = AES_ECB(K_enc, SSC).
// Data is ISO 9797-1 method 2 padded, then encrypted with NO additional padding.
func (ctx *Context) encryptData(data []byte) ([]byte, error) {
	padded := crypto.ISO9797Method2Pad(data, ctx.BlockSize)

	iv, err := ctx.computeIV()
	if err != nil {
		return nil, fmt.Errorf("failed to compute IV: %w", err)
	}

	if ctx.UseAES {
		return crypto.AESEncryptCBCRaw(ctx.EncryptionKey, iv, padded)
	}

	return nil, fmt.Errorf("DES/3DES secure messaging is disabled")
}

// decryptData decrypts data from DO87 using AES-CBC with IV = AES_ECB(K_enc, SSC).
func (ctx *Context) decryptData(encrypted []byte) ([]byte, error) {
	iv, err := ctx.computeIV()
	if err != nil {
		return nil, fmt.Errorf("failed to compute IV: %w", err)
	}

	var padded []byte
	if ctx.UseAES {
		padded, err = crypto.AESDecryptCBCRaw(ctx.EncryptionKey, iv, encrypted)
	} else {
		return nil, fmt.Errorf("DES/3DES secure messaging is disabled")
	}
	if err != nil {
		return nil, err
	}

	return crypto.ISO9797Method2Unpad(padded)
}

// buildDO constructs a data object with tag and length.
func buildDO(tag byte, value []byte) []byte {
	length := len(value)

	if length < 128 {
		// Short form: tag || length || value
		return append([]byte{tag, byte(length)}, value...)
	}

	// Long form: tag || 0x81 || length || value
	return append([]byte{tag, 0x81, byte(length)}, value...)
}

// parseDOLength parses the length field of a data object.
// Returns the length and the number of bytes consumed.
func parseDOLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}

	if data[0] < 128 {
		// Short form
		return int(data[0]), 1
	}

	if data[0] == 0x81 && len(data) >= 2 {
		// Long form (1 byte)
		return int(data[1]), 2
	}

	if data[0] == 0x82 && len(data) >= 3 {
		// Long form (2 bytes)
		return int(binary.BigEndian.Uint16(data[1:3])), 3
	}

	return 0, 0
}
