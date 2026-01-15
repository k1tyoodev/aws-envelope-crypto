import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .envelope import decrypt, encrypt, file_sha256, generate_dek, secure_zero
from .kms import KMSClient

__all__ = [
    "DecryptResult",
    "encrypt_file",
    "encrypt_files_shared_dek",
    "decrypt_file",
    "decrypt_files_parallel",
    "load_dek_from_file",
    "encrypt_file_with_dek",
    "encrypt_files_with_existing_dek",
    "update_manifest",
    "find_manifest_path",
    "validate_manifest_key_file",
]


class DEKDecryptionError(Exception):
    pass


class ManifestKeyMismatchError(Exception):
    pass


@dataclass
class DecryptResult:
    rel_path: str
    success: bool
    error: str | None = None


def encrypt_file(
    input_path: Path,
    output_dir: Path,
    kms: KMSClient,
) -> tuple[Path, Path]:
    dek = generate_dek()
    try:
        data = input_path.read_bytes()
        encrypted_data = encrypt(data, dek)
        encrypted_dek = kms.encrypt_dek(bytes(dek))

        enc_file = output_dir / f"{input_path.name}.enc"
        key_file = output_dir / f"{input_path.name}.key"

        enc_file.write_bytes(encrypted_data)
        key_file.write_bytes(encrypted_dek)

        return enc_file, key_file
    finally:
        secure_zero(dek)


def encrypt_files_shared_dek(
    files: list[Path],
    output_dir: Path,
    kms: KMSClient,
    base_dir: Path | None = None,
) -> tuple[list[Path], Path, Path]:
    dek = generate_dek()
    try:
        encrypted_dek = kms.encrypt_dek(bytes(dek))

        key_file = output_dir / "shared.key"
        key_file.write_bytes(encrypted_dek)

        file_entries = [
            {
                "path": str(f.relative_to(base_dir) if base_dir else Path(f.name)),
                "sha256": file_sha256(f),
            }
            for f in files
        ]

        manifest = {
            "files": file_entries,
            "key_file": "shared.key",
        }
        manifest_file = output_dir / "manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2))

        enc_files = []
        for f, entry in zip(files, file_entries, strict=True):
            data = f.read_bytes()
            encrypted_data = encrypt(data, dek)

            enc_rel_path = Path(entry["path"] + ".enc")
            enc_file = output_dir / enc_rel_path
            enc_file.parent.mkdir(parents=True, exist_ok=True)
            enc_file.write_bytes(encrypted_data)
            enc_files.append(enc_file)

        return enc_files, key_file, manifest_file
    finally:
        secure_zero(dek)


def decrypt_file(
    enc_path: Path,
    key_path: Path,
    kms: KMSClient,
    output_path: Path,
) -> None:
    encrypted_dek = key_path.read_bytes()
    dek = bytearray(kms.decrypt_dek(encrypted_dek))
    try:
        encrypted_data = enc_path.read_bytes()
        data = decrypt(encrypted_data, dek)
        output_path.write_bytes(data)
    finally:
        secure_zero(dek)


def _decrypt_single_file(
    enc_path: Path,
    out_path: Path,
    rel_path: str,
    expected_hash: str | None,
    dek: bytearray,
) -> DecryptResult:
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        encrypted_data = enc_path.read_bytes()
        data = decrypt(encrypted_data, dek)
        out_path.write_bytes(data)

        if expected_hash:
            actual_hash = file_sha256(out_path)
            if actual_hash != expected_hash:
                out_path.unlink(missing_ok=True)
                return DecryptResult(
                    rel_path=rel_path,
                    success=False,
                    error=f"Hash mismatch: expected {expected_hash[:16]}..., "
                    f"got {actual_hash[:16]}...",
                )

        return DecryptResult(rel_path=rel_path, success=True)
    except Exception as e:
        return DecryptResult(rel_path=rel_path, success=False, error=str(e))


def decrypt_files_parallel(
    manifest_path: Path,
    output_dir: Path,
    kms: KMSClient,
    num_workers: int = 4,
) -> list[DecryptResult]:
    manifest = json.loads(manifest_path.read_text())
    base_dir = manifest_path.parent

    key_file = base_dir / manifest["key_file"]
    encrypted_dek = key_file.read_bytes()
    dek = bytearray(kms.decrypt_dek(encrypted_dek))

    try:
        file_entries = manifest["files"]
        if file_entries and isinstance(file_entries[0], str):
            file_entries = [{"path": f, "sha256": None} for f in file_entries]

        tasks = [
            (
                base_dir / f"{entry['path']}.enc",
                output_dir / entry["path"],
                entry["path"],
                entry.get("sha256"),
            )
            for entry in file_entries
        ]

        results = []
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(_decrypt_single_file, *task, dek): task for task in tasks
            }
            for future in as_completed(futures):
                results.append(future.result())

        return results
    finally:
        secure_zero(dek)


def load_dek_from_file(key_path: Path, kms: KMSClient) -> bytearray:
    if not key_path.exists():
        raise FileNotFoundError(f"DEK file not found: {key_path}")
    if key_path.stat().st_size == 0:
        raise ValueError(f"DEK file is empty: {key_path}")

    encrypted_dek = key_path.read_bytes()
    try:
        return bytearray(kms.decrypt_dek(encrypted_dek))
    except Exception as e:
        raise DEKDecryptionError(f"Failed to decrypt DEK: {e}") from e


def encrypt_file_with_dek(
    input_path: Path,
    output_dir: Path,
    dek: bytearray,
    output_name: str | None = None,
) -> tuple[Path, str]:
    data = input_path.read_bytes()
    original_hash = file_sha256(input_path)
    encrypted_data = encrypt(data, dek)

    enc_name = output_name or f"{input_path.name}.enc"
    enc_file = output_dir / enc_name
    enc_file.parent.mkdir(parents=True, exist_ok=True)
    enc_file.write_bytes(encrypted_data)

    return enc_file, original_hash


def encrypt_files_with_existing_dek(
    files: list[Path],
    output_dir: Path,
    kms: KMSClient,
    key_file: Path,
    base_dir: Path | None = None,
) -> tuple[list[Path], dict[str, str]]:
    dek = load_dek_from_file(key_file, kms)
    try:
        enc_files = []
        file_hashes: dict[str, str] = {}

        for f in files:
            rel_path = str(f.relative_to(base_dir) if base_dir else f.name)
            enc_rel_path = f"{rel_path}.enc"

            enc_file, original_hash = encrypt_file_with_dek(f, output_dir, dek, enc_rel_path)
            enc_files.append(enc_file)
            file_hashes[rel_path] = original_hash

        return enc_files, file_hashes
    finally:
        secure_zero(dek)


def update_manifest(
    manifest_path: Path,
    file_updates: dict[str, str],
    add_missing: bool = False,
) -> None:
    manifest = json.loads(manifest_path.read_text())

    existing_paths = {entry["path"] for entry in manifest["files"]}

    for entry in manifest["files"]:
        if entry["path"] in file_updates:
            entry["sha256"] = file_updates[entry["path"]]

    if add_missing:
        for path, sha256 in file_updates.items():
            if path not in existing_paths:
                manifest["files"].append({"path": path, "sha256": sha256})

    manifest_path.write_text(json.dumps(manifest, indent=2))


def find_manifest_path(manifest_path: Path, filename: str) -> str | None:
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if Path(entry["path"]).name == filename:
            return entry["path"]
    return None


def validate_manifest_key_file(manifest_path: Path, key_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text())
    manifest_key = manifest.get("key_file")
    if manifest_key and Path(manifest_key).name != key_path.name:
        raise ManifestKeyMismatchError(
            f"DEK file mismatch: manifest expects '{manifest_key}', got '{key_path.name}'"
        )
