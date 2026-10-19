"""Ed25519 signing for policy files, so a tampered policy is refused at load."""
from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SignatureError(Exception):
    pass


def keygen(private_out: str | Path, public_out: str | Path) -> None:
    key = Ed25519PrivateKey.generate()
    Path(private_out).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    Path(public_out).write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    Path(private_out).chmod(0o600)


def sign_file(path: str | Path, private_key: str | Path) -> Path:
    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    sig = key.sign(Path(path).read_bytes())
    out = Path(str(path) + ".sig")
    out.write_bytes(sig)
    return out


def verify_file(path: str | Path, public_key: str | Path) -> None:
    pub = serialization.load_pem_public_key(Path(public_key).read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        raise SignatureError("public key is not Ed25519")
    sig_path = Path(str(path) + ".sig")
    if not sig_path.exists():
        raise SignatureError(f"missing signature {sig_path}")
    try:
        pub.verify(sig_path.read_bytes(), Path(path).read_bytes())
    except InvalidSignature as e:
        raise SignatureError(f"policy {path} has been modified since it was signed") from e
