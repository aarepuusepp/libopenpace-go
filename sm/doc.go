// Package sm implements Secure Messaging for smart card communication.
//
// Secure Messaging provides confidentiality and integrity protection for
// APDU commands and responses exchanged between a terminal and a smart card.
//
// This package provides:
//   - APDU wrapping (encryption + MAC)
//   - APDU unwrapping (MAC verification + decryption)
//   - Session state management (SSC, keys)
//   - AES-128/192/256 only (DES/3DES is disabled)
//
// Example usage:
//
//	wrappedAPDU, err := ctx.WrapCommand(0x00, 0xB0, 0x00, 0x00, nil, 256)
//	response, err := card.Transmit(wrappedAPDU)
//	data, sw, err := ctx.UnwrapResponse(response)
//
// References:
//   - BSI TR-03110: Secure Messaging
//   - ISO/IEC 7816-4: Secure messaging
package sm
