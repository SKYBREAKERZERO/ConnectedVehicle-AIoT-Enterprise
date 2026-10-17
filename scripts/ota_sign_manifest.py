"""Offline signing helper. Reads a private key; emits only the public verification request."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connected_vehicle.ota.execution_contracts import SignedManifest, VerificationRequest
from scripts.day17_release import read_json, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Exclusive output also refuses aliases of existing input files.
    if args.output.exists():
        raise FileExistsError("Signing output already exists")
    manifest = SignedManifest.model_validate(read_json(args.manifest))
    with args.private_key.open("rb") as stream:
        value = stream.read(65537)
    if len(value) > 65536:
        raise ValueError("Oversized private key")
    key = serialization.load_pem_private_key(value, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("An Ed25519 signing key is required")
    request = VerificationRequest(
        operation_id=uuid4(),
        key_id=manifest.key_id,
        security_version=manifest.security_version,
        signature=base64.b64encode(key.sign(manifest.canonical())).decode(),
    )
    print(write_json(args.output, request.model_dump(mode="json")))


if __name__ == "__main__":
    main()
