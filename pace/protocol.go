package pace

import (
	"encoding/asn1"
	"fmt"
	
	"github.com/aarepuusepp/libopenpace-go/sm"
)

// PerformPACE executes the full PACE protocol with a smart card.
//
// This function implements the complete PACE protocol as specified in BSI TR-03110:
//  1. MSE:Set AT (set authentication template with OID and parameter ID)
//  2. General Authenticate - Encrypted Nonce
//  3. General Authenticate - Mapping Data
//  4. General Authenticate - Ephemeral Public Key
//  5. General Authenticate - Authentication Token
//
// Parameters:
//   - card: Smart card interface for APDU communication
//   - secret: Shared secret (CAN, PIN, etc.)
//   - protocol: PACE protocol OID
//   - parameterID: Standardized domain parameter ID (8 for P-256, etc.)
//
// Returns a Secure Messaging context ready for protected communication.
//
// Reference: BSI TR-03110 v2.21 Section 4.4
func PerformPACE(card CardInterface, secret *PACESecret, protocol ProtocolOID, parameterID int) (*sm.Context, error) {
	// Initialize PACE context
	ctx := &PACEContext{
		Protocol:    protocol,
		ParameterID: parameterID,
	}
	
	// Set up domain parameters
	err := setupDomainParameters(ctx, parameterID)
	if err != nil {
		return nil, fmt.Errorf("failed to setup domain parameters: %w", err)
	}
	
	// Step 0a: Read EF.CardAccess (FID=011C) to activate PACE
	// This tells the card we want to use PACE
	fmt.Printf("[PACE] Reading EF.CardAccess...\n")
	selectCmd := []byte{0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C}
	resp, err2 := card.Transmit(selectCmd)
	if err2 == nil && len(resp) >= 2 {
		sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
		if sw == 0x9000 {
			// Read the file
			readCmd := []byte{0x00, 0xB0, 0x00, 0x00, 0x00}
			resp, err2 = card.Transmit(readCmd)
			if err2 == nil && len(resp) > 2 {
				fmt.Printf("[PACE] EF.CardAccess read: %d bytes\n", len(resp)-2)
			}
		}
	}
	
	// Step 0b: MSE:Set AT (Manage Security Environment)
	err = mseSetAT(card, protocol, parameterID)
	if err != nil {
		return nil, fmt.Errorf("MSE:Set AT failed: %w", err)
	}
	
	// Step 1: Encrypt nonce and send to card
	encryptedNonce, err := PACE_STEP1_enc_nonce(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 1 failed: %w", err)
	}
	
	// Send encrypted nonce to card via General Authenticate
	cardEncryptedNonce, err := generalAuthenticateStep1(card, encryptedNonce)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 1 failed: %w", err)
	}
	
	// Step 2: Decrypt card's encrypted nonce
	err = PACE_STEP2_dec_nonce(ctx, secret, cardEncryptedNonce)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 2 failed: %w", err)
	}
	
	// Step 3A: Map generator (if needed)
	mappingType := protocol.GetMappingType()
	var mappingData []byte
	
	if mappingType == MappingGeneric {
		// For Generic Mapping, exchange mapping data with card
		mappingData, err = generalAuthenticateStep2(card, nil)
		if err != nil {
			return nil, fmt.Errorf("General Authenticate Step 2 (mapping) failed: %w", err)
		}
	}
	
	err = PACE_STEP3A_map_generator(ctx, mappingData)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3A failed: %w", err)
	}
	
	// Step 3B: Generate ephemeral keypair and exchange with card
	ourPublicKey, err := PACE_STEP3B_generate_ephemeral_key(ctx)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3B (generate key) failed: %w", err)
	}
	
	// Exchange ephemeral public keys
	cardPublicKey, err := generalAuthenticateStep3(card, ourPublicKey)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 3 (key exchange) failed: %w", err)
	}
	
	// Compute shared secret from card's public key
	err = PACE_STEP3B_compute_shared_secret(ctx, cardPublicKey)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3B (compute secret) failed: %w", err)
	}
	
	// Step 3C: Derive session keys
	err = PACE_STEP3C_derive_keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3C failed: %w", err)
	}
	
	// Step 3D: Mutual authentication
	ourAuthToken, err := PACE_STEP3D_compute_auth_token(ctx, true) // true = we are terminal
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3D (compute token) failed: %w", err)
	}
	
	// Exchange authentication tokens
	cardAuthToken, err := generalAuthenticateStep4(card, ourAuthToken)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 4 (auth) failed: %w", err)
	}
	
	// Verify card's authentication token
	err = PACE_STEP3D_verify_auth_token(ctx, cardAuthToken, false) // false = card is not terminal
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3D (verify token) failed: %w", err)
	}
	
	// Initialize SSC to zero (as per OpenPACE and BSI TR-03110)
	initialSSC := make([]byte, 8) // All zeros
	
	// Create Secure Messaging context
	smCtx, err := sm.NewContext(ctx.EncryptionKey, ctx.MACKey, initialSSC)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM context: %w", err)
	}
	
	return smCtx, nil
}

// selectApplication selects an application by AID.
//
// Command: 00 A4 04 0C <AID> (P2=0C for contactless)
func selectApplication(card CardInterface, aid []byte) error {
	// For contactless cards, use P2=0C (first or only occurrence)
	cmd := []byte{0x00, 0xA4, 0x04, 0x0C, byte(len(aid))}
	cmd = append(cmd, aid...)
	
	resp, err := card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("SELECT AID transmission failed: %w", err)
	}
	
	if len(resp) < 2 {
		return fmt.Errorf("SELECT AID response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return fmt.Errorf("SELECT AID failed: SW=%04X", sw)
	}
	
	return nil
}

// mseSetAT sends MSE:Set AT command to set up PACE parameters.
//
// Command: 00 22 C1 A4 <data>
// Data: TLV with OID and parameter ID
func mseSetAT(card CardInterface, protocol ProtocolOID, parameterID int) error {
	// Build MSE:Set AT data
	// Tag 80: OID
	// Tag 84: Parameter ID (optional)
	
	oidSlice := protocol.ToOIDSlice()
	oidBytes, err := asn1.Marshal(asn1.ObjectIdentifier(oidSlice))
	if err != nil {
		return fmt.Errorf("failed to marshal OID: %w", err)
	}
	
	fmt.Printf("[PACE] MSE:Set AT - OID: %v, OID bytes: %X\n", oidSlice, oidBytes)
	
	data := []byte{0x80, byte(len(oidBytes))}
	data = append(data, oidBytes...)
	
	if parameterID > 0 {
		data = append(data, 0x84, 0x01, byte(parameterID))
	}
	
	fmt.Printf("[PACE] MSE:Set AT data: %X\n", data)
	
	// MSE:Set AT command
	cmd := []byte{0x00, 0x22, 0xC1, 0xA4, byte(len(data))}
	cmd = append(cmd, data...)
	
	fmt.Printf("[PACE] MSE:Set AT command: %X\n", cmd)
	
	resp, err := card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("MSE:Set AT transmission failed: %w", err)
	}
	
	if len(resp) < 2 {
		return fmt.Errorf("MSE:Set AT response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return fmt.Errorf("MSE:Set AT failed: SW=%04X", sw)
	}
	
	return nil
}

// generalAuthenticateStep1 sends the encrypted nonce to the card.
//
// Command: 00 86 00 00 <data> 00
// Data: Tag 7C { Tag 80 <encrypted_nonce> }
func generalAuthenticateStep1(card CardInterface, encryptedNonce []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 80: Encrypted Nonce
	
	data := []byte{0x7C}
	innerData := []byte{0x80, byte(len(encryptedNonce))}
	innerData = append(innerData, encryptedNonce...)
	data = append(data, byte(len(innerData)))
	data = append(data, innerData...)
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0 (expect response)
	
	resp, err2 := card.Transmit(cmd)
	if err2 != nil {
		return nil, fmt.Errorf("General Authenticate Step 1 transmission failed: %w", err2)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 1 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 1 failed: SW=%04X", sw)
	}
	
	// Parse response: Tag 7C { Tag 80 <card_encrypted_nonce> }
	respData := resp[:len(resp)-2]
	if len(respData) < 4 || respData[0] != 0x7C {
		return nil, fmt.Errorf("invalid response format")
	}
	
	// Extract encrypted nonce from Tag 80
	innerResp := respData[2:]
	if len(innerResp) < 2 || innerResp[0] != 0x80 {
		return nil, fmt.Errorf("missing Tag 80 in response")
	}
	
	nonceLen := int(innerResp[1])
	if len(innerResp) < 2+nonceLen {
		return nil, fmt.Errorf("incomplete encrypted nonce")
	}
	
	return innerResp[2 : 2+nonceLen], nil
}

// generalAuthenticateStep2 exchanges mapping data (for Generic Mapping only).
func generalAuthenticateStep2(card CardInterface, mappingData []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 81: Mapping Data (optional)
	
	var data []byte
	if mappingData != nil {
		data = []byte{0x7C}
		innerData := []byte{0x81, byte(len(mappingData))}
		innerData = append(innerData, mappingData...)
		data = append(data, byte(len(innerData)))
		data = append(data, innerData...)
	} else {
		data = []byte{0x7C, 0x00}
	}
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0
	
	resp, err2 := card.Transmit(cmd)
	if err2 != nil {
		return nil, fmt.Errorf("General Authenticate Step 2 transmission failed: %w", err2)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 2 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 2 failed: SW=%04X", sw)
	}
	
	// Parse response for mapping data if present
	respData := resp[:len(resp)-2]
	if len(respData) > 0 && respData[0] == 0x7C {
		// Extract mapping data from Tag 81
		innerResp := respData[2:]
		if len(innerResp) >= 2 && innerResp[0] == 0x81 {
			dataLen := int(innerResp[1])
			if len(innerResp) >= 2+dataLen {
				return innerResp[2 : 2+dataLen], nil
			}
		}
	}
	
	return nil, nil
}

// generalAuthenticateStep3 exchanges ephemeral public keys.
//
// Command: 00 86 00 00 <data> 00
// Data: Tag 7C { Tag 83 <our_public_key> }
// Response: Tag 7C { Tag 84 <card_public_key> }
func generalAuthenticateStep3(card CardInterface, ourPublicKey []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 83: Terminal Public Key
	
	data := []byte{0x7C}
	innerData := []byte{0x83, byte(len(ourPublicKey))}
	innerData = append(innerData, ourPublicKey...)
	data = append(data, byte(len(innerData)))
	data = append(data, innerData...)
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0
	
	resp, err3 := card.Transmit(cmd)
	if err3 != nil {
		return nil, fmt.Errorf("General Authenticate Step 3 transmission failed: %w", err3)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 3 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 3 failed: SW=%04X", sw)
	}
	
	// Parse response: Tag 7C { Tag 84 <card_public_key> }
	respData := resp[:len(resp)-2]
	if len(respData) < 4 || respData[0] != 0x7C {
		return nil, fmt.Errorf("invalid response format")
	}
	
	// Extract public key from Tag 84
	innerResp := respData[2:]
	if len(innerResp) < 2 || innerResp[0] != 0x84 {
		return nil, fmt.Errorf("missing Tag 84 in response")
	}
	
	keyLen := int(innerResp[1])
	if len(innerResp) < 2+keyLen {
		return nil, fmt.Errorf("incomplete public key")
	}
	
	return innerResp[2 : 2+keyLen], nil
}

// generalAuthenticateStep4 exchanges authentication tokens.
//
// Command: 00 86 00 00 <data> 00
// Data: Tag 7C { Tag 85 <our_auth_token> }
// Response: Tag 7C { Tag 86 <card_auth_token> }
func generalAuthenticateStep4(card CardInterface, ourAuthToken []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 85: Terminal Authentication Token
	
	data := []byte{0x7C}
	innerData := []byte{0x85, byte(len(ourAuthToken))}
	innerData = append(innerData, ourAuthToken...)
	data = append(data, byte(len(innerData)))
	data = append(data, innerData...)
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0
	
	resp, err4 := card.Transmit(cmd)
	if err4 != nil {
		return nil, fmt.Errorf("General Authenticate Step 4 transmission failed: %w", err4)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 4 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 4 failed: SW=%04X", sw)
	}
	
	// Parse response: Tag 7C { Tag 86 <card_auth_token> }
	respData := resp[:len(resp)-2]
	if len(respData) < 4 || respData[0] != 0x7C {
		return nil, fmt.Errorf("invalid response format")
	}
	
	// Extract auth token from Tag 86
	innerResp := respData[2:]
	if len(innerResp) < 2 || innerResp[0] != 0x86 {
		return nil, fmt.Errorf("missing Tag 86 in response")
	}
	
	tokenLen := int(innerResp[1])
	if len(innerResp) < 2+tokenLen {
		return nil, fmt.Errorf("incomplete auth token")
	}
	
	return innerResp[2 : 2+tokenLen], nil
}

