# libopenpace-go 1.1.3 (2026-10-31)

Case-1 secure-messaging commands (no command data and no Le) previously
added a second ISO 9797 padding block after the already padded header.
The MAC now authenticates SSC plus the padded header; a data-object tail
is padded only when present. This fixes SELECT MF SW=6988 on an IDEMIA card.

Independent OpenSSL 3.5.7 AES-128/256 CMAC vectors cover the complete protected
command in TestWrapCommandCase1IndependentCMAC. Existing command-data and
response tests remain in place. KDF and supported PACE profiles are unchanged
from 1.1.2; IM and 3DES remain unsupported.

Hardware acceptance on 2026-10-31: direct IDEMIA NFC CDOC v1 decryption
returned both payloads without writing plaintext to disk. The user subsequently
confirmed NFC decryption in Digisign with the updated installed reader.
This does not establish Thales or real-card CDOC2 acceptance.

Validation commands: GOWORK=off go test ./... and GOWORK=off go vet ./...
