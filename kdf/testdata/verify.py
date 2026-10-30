"""Verify committed fixtures independently of Go, with Python hashlib and OpenSSL."""
import hashlib
import json
import subprocess
from pathlib import Path

vectors = json.loads(Path(__file__).with_name("reference.json").read_text())
for vector in vectors:
    algorithm = "sha1" if vector["keyLength"] == 16 else "sha256"
    counter = {"enc": 1, "mac": 2, "pi": 3}[vector["operation"]]
    data = bytes.fromhex(vector["secret"] + vector["nonce"]) + counter.to_bytes(4, "big")
    expected = bytes.fromhex(vector["expected"])
    python_digest = hashlib.new(algorithm, data).digest()[:len(expected)]
    openssl_digest = subprocess.run(
        ["openssl", "dgst", "-" + algorithm, "-binary"],
        input=data, capture_output=True, check=True,
    ).stdout[:len(expected)]
    if python_digest != expected or openssl_digest != expected:
        raise SystemExit("FAIL " + vector["name"])
print(f"PASS: {len(vectors)} fixed vectors verified with hashlib and OpenSSL")
