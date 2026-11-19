"""Authenticated new encryption and exact legacy-format compatibility."""
import io
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import pyAesCrypt
from .core import AnalysisError, MAX_UPLOAD, validate_bytes

MAGIC = b'MG-AES-GCM\x01'


def _key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        raise AnalysisError('Enter a password of 1–1024 characters.')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))


def encrypt(data: bytes, password: str, algorithm: str = 'AES-GCM') -> bytes:
    validate_bytes(data, allow_empty=True)
    if algorithm == 'AES-GCM':
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        header = MAGIC + salt + nonce
        return header + AESGCM(_key(password, salt)).encrypt(nonce, data, header)
    if algorithm == 'AES Crypt (legacy)':
        _check_password(password)
        output = io.BytesIO()
        pyAesCrypt.encryptStream(io.BytesIO(data), output, password, 65536)
        return output.getvalue()
    if algorithm == 'DES (legacy)':
        return DES.new(_des_key(password), DES.MODE_ECB).encrypt(pad(data, 8))
    raise AnalysisError('Unknown encryption algorithm.')


def _check_password(password: str) -> None:
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        raise AnalysisError('Enter a password of 1–1024 characters.')


def _des_key(password: str) -> bytes:
    _check_password(password)
    key = password[:8].ljust(8, '0').encode('utf-8')
    if len(key) != 8:
        raise AnalysisError('Legacy DES requires an ASCII key (first 8 characters, padded with zeros).')
    return key


def decrypt(data: bytes, password: str, algorithm: str = 'Auto AES') -> bytes:
    validate_bytes(data, MAX_UPLOAD + 65536)
    try:
        if algorithm == 'DES (legacy)':
            return unpad(DES.new(_des_key(password), DES.MODE_ECB).decrypt(data), 8)
        if data.startswith(MAGIC):
            offset = len(MAGIC)
            if len(data) < offset + 44:
                raise AnalysisError('Encrypted file is truncated.')
            salt, nonce = data[offset:offset+16], data[offset+16:offset+28]
            return AESGCM(_key(password, salt)).decrypt(nonce, data[offset+28:], data[:offset+28])
        if data.startswith(b'AES'):
            _check_password(password)
            output = io.BytesIO()
            pyAesCrypt.decryptStream(io.BytesIO(data), output, password, 65536)
            return output.getvalue()
        raise AnalysisError('Unknown format. Choose DES explicitly for legacy DES files.')
    except (InvalidTag, ValueError, EOFError) as exc:
        if isinstance(exc, AnalysisError):
            raise
        raise AnalysisError('Decryption failed: incorrect password or damaged ciphertext.') from None
