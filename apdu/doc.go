// Package apdu provides utilities for working with APDU (Application Protocol Data Unit) commands.
//
// This package includes:
//   - APDU construction and parsing
//   - Status word interpretation
//   - Command/response formatting
//   - Data object (DO) encoding/decoding
//
// APDUs are the fundamental communication unit between a terminal and a smart card.
// They consist of a command APDU sent to the card and a response APDU returned by the card.
//
// Example usage:
//
//	cmd := apdu.NewCommand(0x00, 0xA4, 0x04, 0x00, data)
//	resp, err := card.Transmit(cmd.Bytes())
//	sw := apdu.StatusWord(resp)
//
// References:
//   - ISO/IEC 7816-4: APDU structure
//   - BSI TR-03110: Secure Messaging APDUs
package apdu

