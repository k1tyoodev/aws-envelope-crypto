import json
from pathlib import Path

import pytest

from aws_envelope_crypto import (
    DEKDecryptionError,
    ManifestKeyMismatchError,
    decrypt,
    encrypt,
    encrypt_file_with_dek,
    encrypt_files_with_existing_dek,
    find_manifest_path,
    generate_dek,
    load_dek_from_file,
    update_manifest,
    validate_manifest_key_file,
)
from aws_envelope_crypto.envelope import secure_zero


class MockKMSClient:
    def __init__(self):
        self._stored_dek: bytes | None = None

    def encrypt_dek(self, dek: bytes) -> bytes:
        self._stored_dek = dek
        return b"ENCRYPTED:" + dek

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        if encrypted_dek.startswith(b"ENCRYPTED:"):
            return encrypted_dek[10:]
        raise ValueError("Invalid encrypted DEK format")


@pytest.fixture
def mock_kms():
    return MockKMSClient()


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def sample_dek():
    return generate_dek()


@pytest.fixture
def sample_file(temp_dir):
    file_path = temp_dir / "sample.pth"
    file_path.write_bytes(b"sample model weights data " * 100)
    return file_path


@pytest.fixture
def sample_key_file(temp_dir, sample_dek, mock_kms):
    key_path = temp_dir / "shared.key"
    encrypted_dek = mock_kms.encrypt_dek(bytes(sample_dek))
    key_path.write_bytes(encrypted_dek)
    return key_path


@pytest.fixture
def sample_manifest(temp_dir):
    manifest_path = temp_dir / "manifest.json"
    manifest = {
        "files": [
            {"path": "model.pth", "sha256": "abc123"},
            {"path": "config.pth", "sha256": "def456"},
        ],
        "key_file": "shared.key",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest_path


class TestUpdateManifest:
    def test_update_existing_file_hash(self, sample_manifest):
        update_manifest(sample_manifest, {"model.pth": "new_hash_123"})

        manifest = json.loads(sample_manifest.read_text())
        model_entry = next(e for e in manifest["files"] if e["path"] == "model.pth")
        config_entry = next(e for e in manifest["files"] if e["path"] == "config.pth")

        assert model_entry["sha256"] == "new_hash_123"
        assert config_entry["sha256"] == "def456"

    def test_update_multiple_files(self, sample_manifest):
        update_manifest(
            sample_manifest,
            {"model.pth": "hash1", "config.pth": "hash2"},
        )

        manifest = json.loads(sample_manifest.read_text())
        model_entry = next(e for e in manifest["files"] if e["path"] == "model.pth")
        config_entry = next(e for e in manifest["files"] if e["path"] == "config.pth")

        assert model_entry["sha256"] == "hash1"
        assert config_entry["sha256"] == "hash2"

    def test_add_missing_file(self, sample_manifest):
        update_manifest(
            sample_manifest,
            {"new_file.pth": "new_hash"},
            add_missing=True,
        )

        manifest = json.loads(sample_manifest.read_text())
        paths = [e["path"] for e in manifest["files"]]

        assert "new_file.pth" in paths
        new_entry = next(e for e in manifest["files"] if e["path"] == "new_file.pth")
        assert new_entry["sha256"] == "new_hash"

    def test_no_add_missing_by_default(self, sample_manifest):
        update_manifest(sample_manifest, {"new_file.pth": "new_hash"})

        manifest = json.loads(sample_manifest.read_text())
        paths = [e["path"] for e in manifest["files"]]

        assert "new_file.pth" not in paths

    def test_preserves_key_file(self, sample_manifest):
        update_manifest(sample_manifest, {"model.pth": "new_hash"})

        manifest = json.loads(sample_manifest.read_text())
        assert manifest["key_file"] == "shared.key"


class TestEncryptFileWithDek:
    def test_encrypts_file_successfully(self, sample_file, temp_dir, sample_dek):
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        enc_file, file_hash = encrypt_file_with_dek(sample_file, output_dir, sample_dek)

        assert enc_file.exists()
        assert enc_file.name == "sample.pth.enc"
        assert len(file_hash) == 64

    def test_encrypted_file_can_be_decrypted(self, sample_file, temp_dir, sample_dek):
        output_dir = temp_dir / "output"
        output_dir.mkdir()
        original_data = sample_file.read_bytes()

        enc_file, _ = encrypt_file_with_dek(sample_file, output_dir, sample_dek)
        encrypted_data = enc_file.read_bytes()
        decrypted_data = decrypt(encrypted_data, sample_dek)

        assert decrypted_data == original_data

    def test_custom_output_name(self, sample_file, temp_dir, sample_dek):
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        enc_file, _ = encrypt_file_with_dek(
            sample_file, output_dir, sample_dek, output_name="custom.enc"
        )

        assert enc_file.name == "custom.enc"

    def test_creates_parent_directories(self, sample_file, temp_dir, sample_dek):
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        enc_file, _ = encrypt_file_with_dek(
            sample_file, output_dir, sample_dek, output_name="nested/path/file.enc"
        )

        assert enc_file.exists()
        assert enc_file.parent.name == "path"


class TestLoadDekFromFile:
    def test_loads_and_decrypts_dek(self, sample_key_file, sample_dek, mock_kms):
        loaded_dek = load_dek_from_file(sample_key_file, mock_kms)

        assert bytes(loaded_dek) == bytes(sample_dek)
        assert isinstance(loaded_dek, bytearray)

    def test_returns_bytearray_for_secure_zero(self, sample_key_file, sample_dek, mock_kms):
        loaded_dek = load_dek_from_file(sample_key_file, mock_kms)

        assert isinstance(loaded_dek, bytearray)
        secure_zero(loaded_dek)
        assert all(b == 0 for b in loaded_dek)


class TestEncryptFilesWithExistingDek:
    def test_encrypts_multiple_files(self, temp_dir, mock_kms):
        input_dir = temp_dir / "input"
        input_dir.mkdir()
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        files = []
        for i in range(3):
            f = input_dir / f"model_{i}.pth"
            f.write_bytes(f"data for model {i}".encode() * 100)
            files.append(f)

        dek = generate_dek()
        key_file = temp_dir / "shared.key"
        key_file.write_bytes(mock_kms.encrypt_dek(bytes(dek)))

        enc_files, file_hashes = encrypt_files_with_existing_dek(
            files, output_dir, mock_kms, key_file, base_dir=input_dir
        )

        assert len(enc_files) == 3
        assert len(file_hashes) == 3
        for enc_file in enc_files:
            assert enc_file.exists()
            assert enc_file.suffix == ".enc"

    def test_preserves_relative_paths(self, temp_dir, mock_kms):
        input_dir = temp_dir / "input"
        subdir = input_dir / "subdir"
        subdir.mkdir(parents=True)
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        nested_file = subdir / "nested.pth"
        nested_file.write_bytes(b"nested data" * 100)

        dek = generate_dek()
        key_file = temp_dir / "shared.key"
        key_file.write_bytes(mock_kms.encrypt_dek(bytes(dek)))

        enc_files, file_hashes = encrypt_files_with_existing_dek(
            [nested_file], output_dir, mock_kms, key_file, base_dir=input_dir
        )

        assert "subdir/nested.pth" in file_hashes
        expected_path = output_dir / "subdir" / "nested.pth.enc"
        assert expected_path.exists()

    def test_files_can_be_decrypted(self, temp_dir, mock_kms):
        input_dir = temp_dir / "input"
        input_dir.mkdir()
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        original_data = b"important model weights" * 1000
        sample_file = input_dir / "model.pth"
        sample_file.write_bytes(original_data)

        dek = generate_dek()
        key_file = temp_dir / "shared.key"
        key_file.write_bytes(mock_kms.encrypt_dek(bytes(dek)))

        enc_files, _ = encrypt_files_with_existing_dek(
            [sample_file], output_dir, mock_kms, key_file, base_dir=input_dir
        )

        encrypted_data = enc_files[0].read_bytes()
        decrypted_data = decrypt(encrypted_data, dek)

        assert decrypted_data == original_data


class TestReencryptWorkflow:
    def test_full_reencrypt_workflow(self, temp_dir, mock_kms):
        input_dir = temp_dir / "input"
        input_dir.mkdir()
        encrypted_dir = temp_dir / "encrypted"
        encrypted_dir.mkdir()

        original_file = input_dir / "model.pth"
        original_data = b"original model data" * 1000
        original_file.write_bytes(original_data)

        dek = generate_dek()
        key_file = encrypted_dir / "shared.key"
        key_file.write_bytes(mock_kms.encrypt_dek(bytes(dek)))

        encrypted_data = encrypt(original_data, dek)
        enc_file = encrypted_dir / "model.pth.enc"
        enc_file.write_bytes(encrypted_data)

        from aws_envelope_crypto.envelope import file_sha256

        manifest_path = encrypted_dir / "manifest.json"
        manifest = {
            "files": [{"path": "model.pth", "sha256": file_sha256(original_file)}],
            "key_file": "shared.key",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))

        new_data = b"new corrected model data" * 1000
        new_file = temp_dir / "new_model.pth"
        new_file.write_bytes(new_data)

        loaded_dek = load_dek_from_file(key_file, mock_kms)
        try:
            new_enc_file, new_hash = encrypt_file_with_dek(
                new_file, encrypted_dir, loaded_dek, output_name="model.pth.enc"
            )
        finally:
            secure_zero(loaded_dek)

        update_manifest(manifest_path, {"model.pth": new_hash})

        updated_manifest = json.loads(manifest_path.read_text())
        assert updated_manifest["files"][0]["sha256"] == new_hash

        new_encrypted_data = new_enc_file.read_bytes()
        decrypted_data = decrypt(new_encrypted_data, dek)
        assert decrypted_data == new_data


class TestFindManifestPath:
    def test_finds_path_by_filename(self, temp_dir):
        manifest_path = temp_dir / "manifest.json"
        manifest = {
            "files": [
                {"path": "subdir/model.pth", "sha256": "abc123"},
                {"path": "config.pth", "sha256": "def456"},
            ],
            "key_file": "shared.key",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))

        result = find_manifest_path(manifest_path, "model.pth")
        assert result == "subdir/model.pth"

    def test_returns_none_when_not_found(self, temp_dir):
        manifest_path = temp_dir / "manifest.json"
        manifest = {
            "files": [{"path": "model.pth", "sha256": "abc123"}],
            "key_file": "shared.key",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))

        result = find_manifest_path(manifest_path, "nonexistent.pth")
        assert result is None


class TestValidateManifestKeyFile:
    def test_passes_when_key_matches(self, temp_dir):
        manifest_path = temp_dir / "manifest.json"
        manifest = {
            "files": [{"path": "model.pth", "sha256": "abc123"}],
            "key_file": "shared.key",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))

        key_path = temp_dir / "shared.key"
        validate_manifest_key_file(manifest_path, key_path)

    def test_raises_when_key_mismatches(self, temp_dir):
        manifest_path = temp_dir / "manifest.json"
        manifest = {
            "files": [{"path": "model.pth", "sha256": "abc123"}],
            "key_file": "shared.key",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))

        wrong_key_path = temp_dir / "other.key"
        with pytest.raises(ManifestKeyMismatchError):
            validate_manifest_key_file(manifest_path, wrong_key_path)


class TestLoadDekFromFileErrors:
    def test_raises_on_file_not_found(self, temp_dir, mock_kms):
        nonexistent = temp_dir / "nonexistent.key"
        with pytest.raises(FileNotFoundError):
            load_dek_from_file(nonexistent, mock_kms)

    def test_raises_on_empty_file(self, temp_dir, mock_kms):
        empty_key = temp_dir / "empty.key"
        empty_key.write_bytes(b"")
        with pytest.raises(ValueError, match="empty"):
            load_dek_from_file(empty_key, mock_kms)

    def test_raises_on_decryption_failure(self, temp_dir):
        class FailingKMS:
            def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
                raise Exception("KMS error")

        bad_key = temp_dir / "bad.key"
        bad_key.write_bytes(b"invalid data")
        with pytest.raises(DEKDecryptionError, match="Failed to decrypt"):
            load_dek_from_file(bad_key, FailingKMS())
