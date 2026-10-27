"""Small crypto helpers: commit-reveal and per-tenant sealing."""
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet


def commit(payload: str) -> tuple[str, str]:
    """Return (commitment, nonce). The commitment binds the red team to a
    payload without revealing it: sha256(nonce || payload)."""
    nonce = secrets.token_hex(16)
    return hashlib.sha256((nonce + payload).encode()).hexdigest(), nonce


def verify_commitment(commitment: str, nonce: str, payload: str) -> bool:
    expected = hashlib.sha256((nonce + payload).encode()).hexdigest()
    return hmac.compare_digest(expected, commitment)


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


class Sealer:
    """Encrypts data at rest under a key that belongs to ONE tenant.
    A bug that leaks another tenant's storage still yields only ciphertext."""

    def __init__(self) -> None:
        self._fernet = Fernet(Fernet.generate_key())

    def seal(self, text: str) -> bytes:
        return self._fernet.encrypt(text.encode())

    def unseal(self, blob: bytes) -> str:
        return self._fernet.decrypt(blob).decode()
