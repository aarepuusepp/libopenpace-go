package sm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/aarepuusepp/libopenpace-go/crypto"
)

// Context holds the Secure Messaging session state.
type Context struct {
	EncryptionKey []byte // K_enc for encrypting command data
	MACKey        []byte // K_mac for MAC computation
	SSC           []byte // Send Sequence Counter (8 bytes)
	BlockSize     int    // Cipher block size (8 for 3DES, 16 for AES)
	UseAES        bool   // True for AES, false for 3DES
}

// NewContext creates a new Secure Messaging context.
//
// Parameters:
//   - encKey: Encryption key (16, 24, or 32 bytes for AES; 24 bytes for 3DES)
//   - macKey: MAC key (same length as encryption key)
//   - sscInitial: Initial Send Sequence Counter (8 bytes) as defined by PACE
//
// Returns a new SM context with SSC initialized to sscInitial.
func NewContext(encKey, macKey, sscInitial []byte) (*Context, error) {
	if len(encKey) != len(macKey) {
		return nil, fmt.Errorf("encryption and MAC keys must have the same length")
	}
	if len(sscInitial) != 8 {
		return nil, fmt.Errorf("initial SSC must be 8 bytes")
	}

	// Determine cipher type and block size
	var blockSize int
	var useAES bool

	switch len(encKey) {
	case 16, 32: // AES-128, AES-256
		blockSize = 16
		useAES = true
	case 24: // AES-192 or 3DES - default to AES
		blockSize = 16
		useAES = true
	case 8: // Single DES (not recommended)
		blockSize = 8
		useAES = false
	default:
		return nil, fmt.Errorf("unsupported key length: %d", len(encKey))
	}

	return &Context{
		EncryptionKey: encKey,
		MACKey:        macKey,
		SSC:           append([]byte(nil), sscInitial...), // copy
		BlockSize:     blockSize,
		UseAES:        useAES,
	}, nil
}

// IncrementSSC increments the Send Sequence Counter.
// SSC is an 8-byte big-endian counter.
func (ctx *Context) IncrementSSC() {
	for i := len(ctx.SSC) - 1; i >= 0; i-- {
		ctx.SSC[i]++
		if ctx.SSC[i] != 0 {
			break
		}
	}
}

// SetSSC sets the Send Sequence Counter to the given value.
// The SSC must be 8 bytes.
func (ctx *Context) SetSSC(ssc []byte) error {
	if len(ssc) != 8 {
		return fmt.Errorf("ssc must be 8 bytes")
	}
	ctx.SSC = append(ctx.SSC[:0], ssc...)
	return nil
}

// WrapCommand wraps a command APDU with Secure Messaging.
//
// Process:
//  1. Increment SSC
//  2. Encrypt command data (if present)
//  3. Build DO87 (encrypted data) and DO97 (Le)
//  4. Compute MAC over SSC || header || data objects
//  5. Build DO8E (MAC)
//  6. Construct protected APDU
//
// Parameters:
//   - cla, ins, p1, p2: APDU header
//   - data: Command data (can be empty)
//   - le: Expected response length (0 for no Le, 256 for Le=00)
//
// Returns the wrapped APDU bytes.
//
// Reference: BSI TR-03110 Secure Messaging
func (ctx *Context) WrapCommand(cla, ins, p1, p2 byte, data []byte, le int) ([]byte, error) {
	// Increment SSC
	ctx.IncrementSSC()

	// Build data objects
	var dataObjects []byte

	// DO87: Encrypted data (if data is present)
	if len(data) > 0 {
		encryptedData, err := ctx.encryptData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}

		// DO87 = 0x87 || Length || 0x01 || encrypted_data
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

	// Header with SM bits set in CLA
	header := []byte{cla | 0x0C, ins, p1, p2}

	// Compute MAC
	// MAC input: SSC || CLA' || INS || P1 || P2 || data_objects (NO padding for CMAC)
	macInput := make([]byte, 0, 8+4+len(dataObjects))
	macInput = append(macInput, ctx.SSC...)
	macInput = append(macInput, header...)
	macInput = append(macInput, dataObjects...)

	// Compute MAC (CMAC applies its own padding)
	mac, err := crypto.CMAC(ctx.MACKey, macInput)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}

	// DO8E: MAC (8 bytes)
	do8E := buildDO(0x8E, mac[:8])

	// Build protected APDU
	// CLA' INS P1 P2 Lc' [DO87] [DO97] DO8E
	protectedAPDU := make([]byte, 0, 4+1+len(dataObjects)+len(do8E))
	protectedAPDU = append(protectedAPDU, header...)

	// Lc' = length of data objects + DO8E
	lc := len(dataObjects) + len(do8E)
	protectedAPDU = append(protectedAPDU, byte(lc))

	// Data objects
	protectedAPDU = append(protectedAPDU, dataObjects...)
	protectedAPDU = append(protectedAPDU, do8E...)

	// NOTE: No Le' is appended here. Le is carried in DO97 when needed.

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

	// Verify MAC
	// MAC input: SSC || data_objects_without_MAC (NO padding for CMAC)
	macInput := make([]byte, 0, 8+len(data)-len(mac)-2)
	macInput = append(macInput, ctx.SSC...)
	macInput = append(macInput, data[:len(data)-len(mac)-2]...) // Exclude DO8E (tag+len+val)

	// Compute expected MAC
	expectedMAC, err := crypto.CMAC(ctx.MACKey, macInput)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute MAC: %w", err)
	}

	// Compare MACs (constant-time)
	if len(mac) != 8 || !bytes.Equal(mac, expectedMAC[:8]) {
		return nil, 0, fmt.Errorf("MAC verification failed")
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

// encryptData encrypts data for DO87.
func (ctx *Context) encryptData(data []byte) ([]byte, error) {
	// Pad data
	padded := crypto.ISO9797Method2Pad(data, ctx.BlockSize)

	// Encrypt with zero IV
	iv := make([]byte, ctx.BlockSize)

	var encrypted []byte
	var err error

	if ctx.UseAES {
		encrypted, err = crypto.AESEncryptCBC(ctx.EncryptionKey, iv, padded)
	} else {
		encrypted, err = crypto.TripleDESEncryptCBC(ctx.EncryptionKey, iv, padded)
	}

	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// decryptData decrypts data from DO87.
func (ctx *Context) decryptData(encrypted []byte) ([]byte, error) {
	// Decrypt with zero IV
	iv := make([]byte, ctx.BlockSize)

	var padded []byte
	var err error

	if ctx.UseAES {
		padded, err = crypto.AESDecryptCBC(ctx.EncryptionKey, iv, encrypted)
	} else {
		padded, err = crypto.TripleDESDecryptCBC(ctx.EncryptionKey, iv, encrypted)
	}

	if err != nil {
		return nil, err
	}

	// Unpad
	plaintext, err := crypto.ISO9797Method2Unpad(padded)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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
