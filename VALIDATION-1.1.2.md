# libopenpace-go 1.1.2 validation (2026-10-30)

Windows x64, Go 1.27.3.

Passed:
- go test -count=1 ./...
- go vet ./...
- go test -race -count=1 ./... (MSYS2 UCRT64 GCC)
- python kdf/testdata/verify.py: all 20 fixed vectors agree with both hashlib
  and OpenSSL. The Git for Windows OpenSSL binary was used; sandboxed execution
  failed to load its runtime, so the verifier ran outside that boundary.
- OpenPACE worked-example AES-128 encrypted nonce and session keys.
- IM/3DES/unknown OID rejection at public entry points and CardAccess selection;
  no MSE/General Authenticate for a rejected advertised variant.
- AES-128/192/256 SM contexts remain usable; manually constructed DES/3DES
  contexts are rejected even for commands without encrypted payload.
- Mutation check in an isolated temporary KDF module: the fixed vectors fail
  when AES-128 is changed back to SHA-256, and independently when the nonce is
  placed after the counter. The working source was never mutated by this check.

Scope:
- No real NFC card exchange was run for this patch.
- No claim of full PACE profile certification, CA/TA/CVC, IM/CAM or 3DES support.
- Go tests use fixed fixtures and need no OpenSSL/Python installation.
- See kdf/testdata/README.md for reference sources and reproduction instructions.
