import ctypes
import hashlib
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16
DEK_SIZE = 32
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB per chunk
VERSION = 2
HEADER_FORMAT = "<BII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def generate_dek() -> bytearray:
    return bytearray(os.urandom(DEK_SIZE))


def secure_zero(data: bytearray) -> None:
    if not isinstance(data, bytearray):
        return
    ctypes.memset(ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data)), 0, len(data))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def encrypt(plaintext: bytes, dek: bytes | bytearray) -> bytes:
    aesgcm = AESGCM(bytes(dek))
    chunks = []
    num_chunks = (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE
    header = struct.pack(HEADER_FORMAT, VERSION, CHUNK_SIZE, num_chunks)

    for i in range(0, len(plaintext), CHUNK_SIZE):
        chunk = plaintext[i : i + CHUNK_SIZE]
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, chunk, header)
        chunks.append(nonce + ciphertext)

    return header + b"".join(chunks)


def decrypt(encrypted: bytes, dek: bytes | bytearray) -> bytes:
    if len(encrypted) < HEADER_SIZE:
        raise ValueError("Ciphertext too short to contain header")

    header = encrypted[:HEADER_SIZE]
    version, chunk_size, num_chunks = struct.unpack_from(HEADER_FORMAT, header)
    if version != VERSION:
        raise ValueError(f"Unsupported encryption version: {version}")

    chunk_encrypted_size = chunk_size + NONCE_SIZE + TAG_SIZE
    if num_chunks == 0:
        if len(encrypted) != HEADER_SIZE:
            raise ValueError("Ciphertext length does not match header")
        return b""

    min_size = HEADER_SIZE + (num_chunks - 1) * chunk_encrypted_size + NONCE_SIZE + TAG_SIZE
    max_size = HEADER_SIZE + num_chunks * chunk_encrypted_size
    if len(encrypted) < min_size or len(encrypted) > max_size:
        raise ValueError("Ciphertext length does not match header")

    aesgcm = AESGCM(bytes(dek))
    plaintext_chunks = []

    for i in range(num_chunks):
        start = HEADER_SIZE + i * chunk_encrypted_size
        end = None if i == num_chunks - 1 else start + chunk_encrypted_size
        chunk_data = encrypted[start:end]

        nonce = chunk_data[:NONCE_SIZE]
        ciphertext = chunk_data[NONCE_SIZE:]
        plaintext_chunks.append(aesgcm.decrypt(nonce, ciphertext, header))

    return b"".join(plaintext_chunks)
