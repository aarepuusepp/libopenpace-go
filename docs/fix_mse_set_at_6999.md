
# Fixing `MSE:Set AT` → `SW=6999` during PACE (Thales test card)

You’ve got PACE scaffolding right, but **`MSE:Set AT` returns 0x6999**. This is *before* SM, so the problem is **the AT context TLV** or the *selected applet*. Below is a precise, drop‑in checklist and code pattern to fix it.

---

## 1) Select the **eID application (AID)** **before** PACE

Some Thales/CosmoX profiles require you to be inside the eID applet **before** running PACE. Do a **plain** (non‑SM) `SELECT AID` first:

```
00 A4 04 00 10 A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 01 00
→ 90 00
```

If you get `6A82` at this step, try the PKCS#15 AID as a fallback:
```
00 A4 04 00 0C A0 00 00 00 63 50 4B 43 53 2D 31 35
→ 90 00
```

**Then** issue `MSE:Set AT` and continue with PACE.

> Rationale: some COS/app profiles bind PACE to the selected AID. Doing MSE on MF context can be rejected (0x6999).

---

## 2) Build `MSE:Set AT` with **three TLVs**: 80 (OID) + 83 (Password Ref) + 84 (ParameterId)

Your current `MSE:Set AT` only has **`80`** (OID) and **`84`** (paramId). **Add `83` (password reference)** for CAN or the card will reject with 0x6999.

- **Tag 80** (Algorithm/OID): from **EF.CardAccess → PACEInfo** (e.g., `06 0A 04 00 7F 00 07 02 02 04 02 02` for ECDH IM AES‑128).  
- **Tag 83** (**Password Reference**): use **`83 01 03`** for **CAN** (common mapping on eID).  
- **Tag 84** (**ParameterId**): 1 byte from **PACEInfo** (don’t hardcode; parse CardAccess). On your card, you assumed `84 01 08`; confirm from CardAccess.

Thus the **data field** becomes:
```
80 <lenOID> <OID-bytes>  83 01 03  84 01 <paramId>
```
…and the full APDU:
```
00 22 C1 A4 <Lc> 80.. 83 01 03 84 01 <paramId>
```

**Example** (OID = `06 0A 04 00 7F 00 07 02 02 04 02 02`, paramId = `08`):
```
00 22 C1 A4 14
80 0C 06 0A 04 00 7F 00 07 02 02 04 02 02
83 01 03
84 01 08
```

> If the card still rejects, try **`83 01 02`** for CAN (some profiles use 0x02 for CAN, 0x03 for PIN; vendor‑specific). Keep 0x03 first.

---

## 3) Parse **EF.CardAccess** and pick OID + ParameterId from the card (don’t guess)

You already read **22 bytes** of CardAccess. Extract **PACEInfo** from `SecurityInfos` and use its values.

Pseudo‑parser (Go):
```go
type PACEInfo struct {
    OID        []byte // DER OID bytes (tag 0x06 ...)
    ParamID    byte   // INTEGER (1 byte typical), used as 0x84 0x01 <id>
    PwType     byte   // choose CAN by mapping to 0x83 01 03 (see below)
}

// returns list of PACEInfos (there can be multiple)
func ParseCardAccessPACEInfos(cardAccess []byte) []PACEInfo { /* ... parse ASN.1 SEQUENCE ... */ }
```

Choose the **first** PACEInfo supporting `ECDH-IM-AES128` and preferred curve, then **use its exact OID and paramId** in MSE.

---

## 4) Full PACE step sequence (no SM yet)

1. (Plain) `SELECT AID` (eID) → `9000`  
2. (Plain) `READ BINARY EF.CardAccess` (optional if already cached)  
3. (Plain) `MSE:Set AT` with **80+83+84** → `9000`  
4. (Plain) `GENERAL AUTHENTICATE` steps 1–4 (PACE) → `9000` on each
5. When PACE completes, you get Kenc/Kmac/SSC0 → switch to **SM** for all subsequent APDUs (CLA |= 0x0C).

---

## 5) Quick instrumentation to prove the fix

Log the exact `MSE:Set AT` **data TLV** you build **and** the `<Lc>`:
- The Lc must match **length(80.. + 83 01 03 + 84 01 xx)**.
- You should see three TLVs in order: **80 … 83 01 03 84 01 …**
- The response should be **`90 00`**. If it’s `6A80` → TLV malformed; `6A81/6A88` → wrong OID; `6999` → wrong/absent `83` or wrong context/app selected.

---

## 6) Drop‑in helper to build MSE:Set AT (Go)

```go
// BuildMSESetATPACE builds: 00 22 C1 A4 Lc  80 <len> <oid>  83 01 <pwRef>  84 01 <paramId>
func BuildMSESetATPACE(oid []byte, pwRef byte, paramId byte) []byte {
    // TLV 80: OID
    tlv80 := append([]byte{0x80, byte(len(oid))}, oid...)
    // TLV 83: PW reference (likely 0x03 for CAN; try 0x02 if 0x03 fails)
    tlv83 := []byte{0x83, 0x01, pwRef}
    // TLV 84: ParameterId
    tlv84 := []byte{0x84, 0x01, paramId}

    data := append(append(tlv80, tlv83...), tlv84...)
    apdu := make([]byte, 0, 5+len(data))
    apdu = append(apdu, 0x00, 0x22, 0xC1, 0xA4, byte(len(data)))
    apdu = append(apdu, data...)
    return apdu
}
```

Usage:
```go
// From EF.CardAccess:
oid := []byte{0x06,0x0A,0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,0x02} // example
paramId := byte(0x08) // example — read from CardAccess!
pwRef := byte(0x03)   // CAN (try 0x02 if needed)

apdu := BuildMSESetATPACE(oid, pwRef, paramId)
data, sw := transmitPlain(apdu)
```

---

## 7) If it still returns `6999`

- Confirm you did a **plain `SELECT AID` first**.
- Verify **`83 01 03` is present** in the data (not 0x84).
- Double‑check the **paramId** is exactly what **CardAccess** says for that OID (not hardcoded 0x08).
- Try **`83 01 02`** in case this COS maps CAN to 0x02.
- As a last resort, try the **PKCS#15 AID** select first, then eID AID, then `MSE:Set AT`.

Once `MSE:Set AT` returns **`90 00`**, your existing GA steps will succeed and you’ll enter SM. From there, your `SELECT DFDD → EF 5001.. → READ BINARY` under SM will work.

---

## Appendix: Why `6999` here
`69 99` at MSE means “security status not satisfied / wrong context” and is commonly returned when the **password reference (83)** is missing/wrong or the operation is attempted **outside the required applet**. Fixing the TLV and doing a **plain AID select** first addresses both.
