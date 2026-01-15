import argparse
import os
import sys
from pathlib import Path

from .envelope import secure_zero
from .kms import KMSClient
from .multi import (
    DEKDecryptionError,
    ManifestKeyMismatchError,
    decrypt_file,
    decrypt_files_parallel,
    encrypt_file,
    encrypt_file_with_dek,
    encrypt_files_shared_dek,
    encrypt_files_with_existing_dek,
    find_manifest_path,
    load_dek_from_file,
    update_manifest,
    validate_manifest_key_file,
)
from .oidc import get_sts_credentials

DEFAULT_REGION = "us-east-1"
WEIGHT_EXTENSIONS = ("*.pth", "*.pkl", "*.t7", "*.pt")


def cmd_encrypt_with_existing_dek(args: argparse.Namespace) -> int:
    if not args.kms_key_id:
        print("Error: --kms-key-id required to decrypt DEK", file=sys.stderr)
        return 1

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    key_path = Path(args.dek_file)
    manifest_path = Path(args.manifest) if args.manifest else None

    if not key_path.exists():
        print(f"Error: DEK file not found: {key_path}", file=sys.stderr)
        return 1

    if manifest_path and manifest_path.exists():
        try:
            validate_manifest_key_file(manifest_path, key_path)
        except ManifestKeyMismatchError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    kms = KMSClient(key_id=args.kms_key_id, region=args.kms_region)

    try:
        dek = load_dek_from_file(key_path, kms)
    except (FileNotFoundError, ValueError, DEKDecryptionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        if input_path.is_file():
            rel_path = input_path.name
            if manifest_path and manifest_path.exists():
                found_path = find_manifest_path(manifest_path, input_path.name)
                if found_path:
                    rel_path = found_path

            enc_file, file_hash = encrypt_file_with_dek(input_path, output_dir, dek)
            print(f"Encrypted: {enc_file.name}")

            if manifest_path and manifest_path.exists():
                update_manifest(manifest_path, {rel_path: file_hash})
                print(f"Updated manifest: {manifest_path}")
        elif input_path.is_dir():
            if args.weights:
                patterns = [f"**/{ext}" if args.recursive else ext for ext in WEIGHT_EXTENSIONS]
                files = sorted({f for p in patterns for f in input_path.glob(p) if f.is_file()})
            else:
                pattern = f"**/{args.pattern}" if args.recursive else args.pattern
                files = sorted(f for f in input_path.glob(pattern) if f.is_file())

            if not files:
                pattern_desc = "weight files" if args.weights else f"'{args.pattern}'"
                print(f"No files matching {pattern_desc} in {input_path}", file=sys.stderr)
                return 1

            total_size_mb = sum(f.stat().st_size for f in files) / 1024 / 1024
            print(f"Found {len(files)} files ({total_size_mb:.1f} MB)")

            enc_files, file_hashes = encrypt_files_with_existing_dek(
                files, output_dir, kms, key_path, base_dir=input_path
            )

            if manifest_path:
                if manifest_path.exists():
                    update_manifest(manifest_path, file_hashes, add_missing=True)
                    print(f"Updated manifest: {manifest_path}")
                else:
                    print(f"Warning: manifest not found: {manifest_path}", file=sys.stderr)

            print(f"Encrypted {len(enc_files)} files with existing DEK")
            print(f"Output: {output_dir}")
        else:
            print(f"Input not found: {input_path}", file=sys.stderr)
            return 1
    finally:
        secure_zero(dek)

    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    if args.dek_file:
        return cmd_encrypt_with_existing_dek(args)

    if not args.kms_key_id:
        print("Error: --kms-key-id or AWS_KMS_KEY_ID required", file=sys.stderr)
        return 1

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    kms = KMSClient(key_id=args.kms_key_id, region=args.kms_region)

    if input_path.is_file():
        enc_file, key_file = encrypt_file(input_path, output_dir, kms)
        print(f"Encrypted: {enc_file.name}, {key_file.name}")
    elif input_path.is_dir():
        if args.weights:
            patterns = [f"**/{ext}" if args.recursive else ext for ext in WEIGHT_EXTENSIONS]
            files = sorted({f for p in patterns for f in input_path.glob(p) if f.is_file()})
        else:
            pattern = f"**/{args.pattern}" if args.recursive else args.pattern
            files = sorted(f for f in input_path.glob(pattern) if f.is_file())
        if not files:
            pattern_desc = "weight files" if args.weights else f"'{args.pattern}'"
            print(f"No files matching {pattern_desc} in {input_path}", file=sys.stderr)
            return 1

        total_size_mb = sum(f.stat().st_size for f in files) / 1024 / 1024
        print(f"Found {len(files)} files ({total_size_mb:.1f} MB)")

        if args.shared_dek:
            enc_files, key_file, manifest_file = encrypt_files_shared_dek(
                files, output_dir, kms, base_dir=input_path
            )
            print(f"Encrypted {len(enc_files)} files with shared DEK")
            print(f"Manifest: {manifest_file.name}")
        else:
            for f in files:
                rel_path = f.relative_to(input_path)
                file_output_dir = output_dir / rel_path.parent
                file_output_dir.mkdir(parents=True, exist_ok=True)
                enc_file, key_file = encrypt_file(f, file_output_dir, kms)
                print(f"Encrypted: {rel_path}")

        print(f"Output: {output_dir}")
    else:
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 1

    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.use_oidc:
        creds = get_sts_credentials(role_arn=args.role_arn, region=args.kms_region)
        kms = KMSClient.from_sts_credentials(
            key_id=args.kms_key_id, credentials=creds, region=args.kms_region
        )
    else:
        kms = KMSClient(key_id=args.kms_key_id, region=args.kms_region)

    if args.manifest:
        manifest_path = Path(args.manifest)
        results = decrypt_files_parallel(manifest_path, output_dir, kms, num_workers=args.workers)

        success_count = 0
        fail_count = 0
        for result in results:
            if result.success:
                out_file = output_dir / result.rel_path
                size_mb = out_file.stat().st_size / 1024 / 1024
                print(f"Decrypted: {result.rel_path} ({size_mb:.1f} MB)")
                success_count += 1
            else:
                print(f"Failed: {result.rel_path} - {result.error}", file=sys.stderr)
                fail_count += 1

        print(f"Output: {output_dir}")
        if fail_count > 0:
            print(f"Warning: {fail_count}/{len(results)} files failed", file=sys.stderr)
            return 1
    elif args.enc and args.key:
        enc_path = Path(args.enc)
        key_path = Path(args.key)

        out_name = enc_path.stem if enc_path.suffix == ".enc" else enc_path.name
        out_file = output_dir / out_name

        decrypt_file(enc_path, key_path, kms, out_file)
        size_mb = out_file.stat().st_size / 1024 / 1024
        print(f"Decrypted: {out_file.name} ({size_mb:.1f} MB)")
    else:
        print("Error: --manifest or (--enc and --key) required", file=sys.stderr)
        return 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aws-envelope-crypto",
        description="AWS KMS envelope encryption with OIDC support",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt files")
    enc.add_argument("--input", "-i", required=True, help="File or directory to encrypt")
    enc.add_argument("--output-dir", "-o", default="./encrypted", help="Output directory")
    enc.add_argument("--pattern", default="*", help="Glob pattern for directory input")
    enc.add_argument(
        "--weights", "-w", action="store_true", help="Match weight files (pth, pkl, t7, pt)"
    )
    enc.add_argument(
        "--recursive", "-r", action="store_true", help="Recursively search subdirectories"
    )
    enc.add_argument("--shared-dek", action="store_true", help="Use single DEK for all files")
    enc.add_argument("--dek-file", "-k", help="Use existing DEK file instead of generating new one")
    enc.add_argument("--manifest", "-m", help="Manifest file to update when using --dek-file")
    enc.add_argument("--kms-key-id", default=os.environ.get("AWS_KMS_KEY_ID"), help="KMS key ID")
    enc.add_argument(
        "--kms-region", default=os.environ.get("AWS_KMS_REGION", DEFAULT_REGION), help="KMS region"
    )

    dec = subparsers.add_parser("decrypt", help="Decrypt files")
    dec.add_argument("--enc", help="Encrypted file path")
    dec.add_argument("--key", help="Key file path")
    dec.add_argument("--manifest", help="manifest.json path for multi-file decrypt")
    dec.add_argument("--output-dir", "-o", required=True, help="Output directory")
    dec.add_argument("--workers", type=int, default=4, help="Parallel workers for multi-file")
    dec.add_argument("--use-oidc", action="store_true", help="Use OIDC for credentials")
    dec.add_argument("--role-arn", default=os.environ.get("AWS_ROLE_ARN"), help="IAM Role ARN")
    dec.add_argument("--kms-key-id", default=os.environ.get("AWS_KMS_KEY_ID"), help="KMS key ID")
    dec.add_argument(
        "--kms-region", default=os.environ.get("AWS_KMS_REGION", DEFAULT_REGION), help="KMS region"
    )

    args = parser.parse_args()

    commands = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
