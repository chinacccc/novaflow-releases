from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
_SAFE_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


def finalize_release(
    *,
    channel: str,
    version: str,
    release_notes: str,
    update_base_url: str,
    update_metadata_path: Path,
    subtitle_manifest_path: Path,
    public_key_path: Path,
    output_root: Path,
) -> tuple[Path, Path]:
    if channel not in {"stable", "beta"} or _VERSION.fullmatch(version) is None:
        raise ValueError("release channel or version is invalid")
    if not 1 <= len(release_notes) <= 20_000:
        raise ValueError("release notes are invalid")
    origin = update_base_url.rstrip("/")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("update origin is invalid")

    metadata = json.loads(update_metadata_path.resolve(strict=True).read_text("utf-8"))
    file_name = metadata.get("file_name")
    size = metadata.get("size")
    digest = metadata.get("sha256")
    if not isinstance(file_name, str) or _SAFE_FILE.fullmatch(file_name) is None:
        raise ValueError("update artifact name is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise ValueError("update artifact size is invalid")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ValueError("update artifact digest is invalid")

    private_text = os.environ.get("NOVAFLOW_UPDATE_SIGNING_KEY_PEM", "").strip()
    if not private_text:
        raise ValueError("GitHub update signing secret is missing")
    private = load_pem_private_key(private_text.replace("\\n", "\n").encode("ascii"), None)
    public = load_pem_public_key(public_key_path.resolve(strict=True).read_bytes())
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("update signing secret is not Ed25519")
    probe = b"novaflow-release-key-match"
    try:
        public.verify(private.sign(probe), probe)
    except Exception as error:
        raise ValueError("update signing secret does not match the public key") from error

    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    subtitle_manifest = subtitle_manifest_path.resolve(strict=True)
    subtitle_signature = output / f"{subtitle_manifest.name}.sig"
    latest = output / "latest.json"
    if subtitle_signature.exists() or latest.exists():
        raise FileExistsError("release finalization output already exists")

    subtitle_body = subtitle_manifest.read_bytes()
    subtitle_signature.write_text(
        base64.b64encode(private.sign(subtitle_body)).decode("ascii") + "\n",
        encoding="ascii",
    )
    payload = {
        "schema_version": 1,
        "channel": channel,
        "version": version,
        "published_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "release_notes": release_notes,
        "artifacts": [
            {
                "kind": "full",
                "platform": "windows-x86_64",
                "file_name": file_name,
                "url": f"{origin}/{channel}/{file_name}",
                "size": size,
                "sha256": digest,
            }
        ],
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload["signature"] = base64.b64encode(private.sign(canonical)).decode("ascii")
    latest.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return latest, subtitle_signature


def finalize_public_unsigned_feed(
    *,
    channel: str,
    version: str,
    release_notes: str,
    update_base_url: str,
    release_metadata_path: Path,
    public_key_path: Path,
    output_root: Path,
) -> Path:
    """Sign a check-only feed for the manual PublicUnsigned install path."""
    if channel != "stable" or _VERSION.fullmatch(version) is None:
        raise ValueError("PublicUnsigned feed must use the stable channel and a valid version")
    if not 1 <= len(release_notes) <= 20_000 or version not in release_notes:
        raise ValueError("release notes must identify the feed version")
    origin = update_base_url.rstrip("/")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("update origin is invalid")

    metadata = json.loads(release_metadata_path.resolve(strict=True).read_text("utf-8"))
    expected_flags = {
        "schema_version": 1,
        "version": version,
        "channel": "stable",
        "mode": "publicunsigned",
        "unsigned_windows_installer": True,
        "manual_stable_download_only": True,
        "automatic_update_manifest_included": False,
    }
    for key, expected in expected_flags.items():
        if metadata.get(key) != expected:
            raise ValueError(f"release metadata {key} is invalid")
    installer = metadata.get("installer")
    if not isinstance(installer, dict):
        raise ValueError("release installer metadata is invalid")
    file_name = installer.get("file_name")
    size = installer.get("size")
    digest = installer.get("sha256")
    expected_name = f"NovaFlow-Next-{version}-Windows-x64-Setup.exe"
    if file_name != expected_name or _SAFE_FILE.fullmatch(file_name) is None:
        raise ValueError("release installer name is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise ValueError("release installer size is invalid")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ValueError("release installer digest is invalid")

    private_text = os.environ.get("NOVAFLOW_UPDATE_SIGNING_KEY_PEM", "").strip()
    if not private_text:
        raise ValueError("GitHub update signing secret is missing")
    private = load_pem_private_key(private_text.replace("\\n", "\n").encode("ascii"), None)
    public = load_pem_public_key(public_key_path.resolve(strict=True).read_bytes())
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("update signing secret is not Ed25519")
    probe = b"novaflow-release-key-match"
    try:
        public.verify(private.sign(probe), probe)
    except Exception as error:
        raise ValueError("update signing secret does not match the public key") from error

    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    latest = output / "latest.json"
    if latest.exists():
        raise FileExistsError("release finalization output already exists")
    payload = {
        "schema_version": 1,
        "channel": "stable",
        "version": version,
        "published_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "release_notes": release_notes,
        "artifacts": [
            {
                "kind": "full",
                "platform": "windows-x86_64",
                "file_name": file_name,
                "url": f"{origin}/stable/{file_name}",
                "size": size,
                "sha256": digest,
            }
        ],
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload["signature"] = base64.b64encode(private.sign(canonical)).decode("ascii")
    latest.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return latest


def main() -> int:
    parser = argparse.ArgumentParser(description="Finalize a zero-cost NovaFlow release")
    parser.add_argument("--mode", choices=("formal", "publicunsigned"), default="formal")
    parser.add_argument("--channel", required=True, choices=("stable", "beta"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-notes", required=True)
    parser.add_argument("--update-base-url", required=True)
    parser.add_argument("--update-metadata", type=Path)
    parser.add_argument("--subtitle-manifest", type=Path)
    parser.add_argument("--release-metadata", type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    arguments = parser.parse_args()
    if arguments.mode == "publicunsigned":
        if arguments.release_metadata is None:
            parser.error("--release-metadata is required for PublicUnsigned")
        paths = (
            finalize_public_unsigned_feed(
                channel=arguments.channel,
                version=arguments.version,
                release_notes=arguments.release_notes,
                update_base_url=arguments.update_base_url,
                release_metadata_path=arguments.release_metadata,
                public_key_path=arguments.public_key,
                output_root=arguments.output_root,
            ),
        )
    else:
        if arguments.update_metadata is None or arguments.subtitle_manifest is None:
            parser.error("--update-metadata and --subtitle-manifest are required for Formal")
        paths = finalize_release(
            channel=arguments.channel,
            version=arguments.version,
            release_notes=arguments.release_notes,
            update_base_url=arguments.update_base_url,
            update_metadata_path=arguments.update_metadata,
            subtitle_manifest_path=arguments.subtitle_manifest,
            public_key_path=arguments.public_key,
            output_root=arguments.output_root,
        )
    for path in paths:
        print(f"{path.name} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
