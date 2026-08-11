from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from cryptography.hazmat.primitives.serialization import load_pem_public_key

_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
_ASSET_VERSION = re.compile(
    r"NovaFlow-Next-([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)-Windows-x64"
)
_TAG_VERSION = re.compile(r"/releases/download/v([^/]+)/")


def _asset_version(file_name: object) -> str:
    if not isinstance(file_name, str):
        raise ValueError("release asset file name is missing")
    match = _ASSET_VERSION.search(file_name)
    if match is None:
        raise ValueError("release asset file name does not contain a NovaFlow version")
    return match.group(1)


def _verify_feed_signature(feed: dict[str, Any], public_key_pem: bytes) -> None:
    signed = dict(feed)
    signature_text = signed.pop("signature", None)
    if not isinstance(signature_text, str):
        raise ValueError("desktop stable feed signature is missing")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        public = load_pem_public_key(public_key_pem)
        canonical = json.dumps(
            signed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        public.verify(signature, canonical)
    except Exception as error:
        raise ValueError("desktop stable feed signature is invalid") from error


def validate_stable_release_consistency(
    *,
    expected_version: str,
    release_metadata: dict[str, Any],
    desktop_feed: dict[str, Any],
    website_download_location: str,
    public_key_pem: bytes,
) -> dict[str, str]:
    if _VERSION.fullmatch(expected_version) is None:
        raise ValueError("expected version is invalid")

    github_version = release_metadata.get("version")
    if github_version != expected_version:
        raise ValueError(
            f"GitHub release version mismatch: expected {expected_version}, got {github_version}"
        )
    if release_metadata.get("channel") != "stable":
        raise ValueError("GitHub release metadata is not stable")
    installer = release_metadata.get("installer")
    if not isinstance(installer, dict):
        raise ValueError("GitHub release installer metadata is missing")
    if _asset_version(installer.get("file_name")) != expected_version:
        raise ValueError("GitHub release installer version mismatch")

    _verify_feed_signature(desktop_feed, public_key_pem)
    if desktop_feed.get("channel") != "stable":
        raise ValueError("desktop update feed is not stable")
    feed_version = desktop_feed.get("version")
    if feed_version != expected_version:
        raise ValueError(
            f"desktop update feed version mismatch: expected {expected_version}, got {feed_version}"
        )
    release_notes = desktop_feed.get("release_notes")
    if not isinstance(release_notes, str) or expected_version not in release_notes:
        raise ValueError("desktop update feed release notes do not identify the feed version")
    artifacts = desktop_feed.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) < 1:
        raise ValueError("desktop update feed has no release artifact")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("desktop update feed artifact is invalid")
        if _asset_version(artifact.get("file_name")) != expected_version:
            raise ValueError("desktop update feed artifact version mismatch")

    parsed_download = urlsplit(website_download_location)
    if parsed_download.scheme != "https" or parsed_download.hostname != "github.com":
        raise ValueError("website stable download does not redirect to GitHub Releases")
    tag_match = _TAG_VERSION.search(parsed_download.path)
    if tag_match is None:
        raise ValueError("website stable download release tag is missing")
    website_version = tag_match.group(1)
    if website_version != expected_version:
        raise ValueError(
            f"website stable version mismatch: expected {expected_version}, got {website_version}"
        )
    if _asset_version(parsed_download.path.rsplit("/", 1)[-1]) != expected_version:
        raise ValueError("website stable installer version mismatch")

    return {
        "expected_version": expected_version,
        "github_release_version": str(github_version),
        "desktop_stable_feed_version": str(feed_version),
        "website_stable_version": website_version,
    }


def _read_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "NovaFlow-release-gate/1"})
    with urlopen(request, timeout=30) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError(f"JSON endpoint did not return an object: {url}")
    return value


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _read_redirect_location(url: str) -> str:
    request = Request(url, headers={"User-Agent": "NovaFlow-release-gate/1"})
    try:
        build_opener(_NoRedirect).open(request, timeout=30)
    except HTTPError as error:
        if error.code not in {301, 302, 303, 307, 308}:
            raise
        location = error.headers.get("Location")
        if location:
            return location
    raise ValueError(f"website download endpoint did not return a redirect: {url}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check NovaFlow stable release consistency")
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--github-release-metadata-url", required=True)
    parser.add_argument("--desktop-feed-url", required=True)
    parser.add_argument("--website-download-url", required=True)
    parser.add_argument("--public-key", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = validate_stable_release_consistency(
            expected_version=arguments.expected_version,
            release_metadata=_read_json(arguments.github_release_metadata_url),
            desktop_feed=_read_json(arguments.desktop_feed_url),
            website_download_location=_read_redirect_location(arguments.website_download_url),
            public_key_pem=arguments.public_key.resolve(strict=True).read_bytes(),
        )
    except Exception as error:
        print(f"stable release consistency FAILED: {error}")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
