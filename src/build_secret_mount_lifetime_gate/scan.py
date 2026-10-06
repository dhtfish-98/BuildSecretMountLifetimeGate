"""Bounded byte scans for local Buildx outputs; no remote inputs are accepted."""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path


MAX_FILE = 256 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_DEPTH = 5
TAR_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
}
GZIP_TAR_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


class ScanIncomplete(Exception):
    """An artifact cannot be fully checked within the declared bounds."""


@dataclass(frozen=True)
class Finding:
    area: str
    location: str
    representation: str


def _inflate_bounded(data: bytes, wbits: int) -> bytes:
    decoder = zlib.decompressobj(wbits)
    expanded = decoder.decompress(data, MAX_EXPANDED + 1)
    if len(expanded) > MAX_EXPANDED or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ScanIncomplete("compressed stream exceeds bound or is incomplete")
    return expanded


def _has_zlib_header(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return (cmf & 15) == 8 and (cmf >> 4) <= 7 and ((cmf << 8) | flg) % 31 == 0


def _tar_checksum_valid(header: bytes) -> bool:
    try:
        expected = tarfile.nti(header[148:156])
    except (tarfile.InvalidHeaderError, ValueError):
        return False
    actual = sum(header[:148]) + 8 * 32 + sum(header[156:])
    return expected == actual


def _looks_like_tar(data: bytes) -> bool:
    return len(data) >= 512 and (
        data[257:262] == b"ustar" or _tar_checksum_valid(data[:512])
    )


def _tar_payloads(data: bytes):
    if len(data) % 512:
        raise ScanIncomplete("TAR length is not a multiple of 512")
    position = 0
    while True:
        if position + 512 > len(data):
            raise ScanIncomplete("TAR has no complete terminator")
        header = data[position : position + 512]
        if header == bytes(512):
            if position + 1024 > len(data) or data[position + 512 : position + 1024] != bytes(512):
                raise ScanIncomplete("TAR lacks two zero terminator blocks")
            if any(data[position + 1024 :]):
                raise ScanIncomplete("TAR has nonzero trailing bytes")
            return
        if not _tar_checksum_valid(header):
            raise ScanIncomplete("TAR header checksum invalid")
        try:
            size = tarfile.nti(header[124:136])
        except (tarfile.InvalidHeaderError, ValueError) as error:
            raise ScanIncomplete("TAR member size invalid") from error
        if size < 0 or size > MAX_FILE:
            raise ScanIncomplete("TAR member size exceeds bound")
        content_start = position + 512
        content_end = content_start + size
        next_header = content_start + ((size + 511) // 512) * 512
        if next_header > len(data) or content_end > len(data):
            raise ScanIncomplete("TAR member payload truncated")
        name = header[:100].split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
        yield name, data[content_start:content_end]
        position = next_header


def _validate_declared_layer(data: bytes, media_type: object) -> None:
    """Use the verified OCI descriptor, not a damaged payload's magic, to choose a parser."""
    if not isinstance(media_type, str):
        raise ScanIncomplete("local cache layer media type is missing or invalid")
    if media_type in TAR_LAYER_TYPES:
        tar_data = data
    elif media_type in GZIP_TAR_LAYER_TYPES:
        if not data.startswith(b"\x1f\x8b"):
            raise ScanIncomplete("declared gzip TAR layer has no gzip header")
        tar_data = _inflate_bounded(data, 16 + zlib.MAX_WBITS)
    else:
        raise ScanIncomplete("local cache layer media type is unsupported")
    for _name, _payload in _tar_payloads(tar_data):
        pass


def _scan_bytes(
    data: bytes, needle: bytes, area: str, location: str, depth: int = 0,
    expected_format: str | None = None,
) -> list[Finding]:
    if depth > MAX_DEPTH:
        raise ScanIncomplete("nested artifact depth exceeds bound")
    if len(data) > MAX_EXPANDED:
        raise ScanIncomplete("artifact component exceeds bound")
    found: list[Finding] = []
    if needle in data:
        found.append(Finding(area, location, "literal"))

    if expected_format == "tar+gzip":
        if not data.startswith(b"\x1f\x8b"):
            raise ScanIncomplete("declared gzip TAR file has no gzip header")
        expanded = _inflate_bounded(data, 16 + zlib.MAX_WBITS)
        found.extend(_scan_bytes(expanded, needle, area, location + "!gzip", depth + 1, "tar"))
        return found
    if expected_format == "tar":
        for name, payload in _tar_payloads(data):
            found.extend(_scan_bytes(payload, needle, area, location + "!" + name, depth + 1))
        return found

    if data.startswith(b"\x1f\x8b"):
        expanded = _inflate_bounded(data, 16 + zlib.MAX_WBITS)
        found.extend(_scan_bytes(expanded, needle, area, location + "!gzip", depth + 1))
        return found
    if _has_zlib_header(data):
        expanded = _inflate_bounded(data, zlib.MAX_WBITS)
        found.extend(_scan_bytes(expanded, needle, area, location + "!zlib", depth + 1))
        return found
    if data.startswith((b"\x28\xb5\x2f\xfd", b"\xfd7zXZ\x00", b"BZh", b"PK\x03\x04", b"\x04\x22\x4d\x18")):
        raise ScanIncomplete("unexpected compressed format cannot be fully scanned")

    if _looks_like_tar(data):
        for name, payload in _tar_payloads(data):
            found.extend(_scan_bytes(payload, needle, area, location + "!" + name, depth + 1))
    return found


def scan_file(path: Path, needle: bytes, area: str) -> list[Finding]:
    if len(needle) < 24:
        raise ValueError("synthetic marker is too short for a meaningful scan")
    if path.stat().st_size > MAX_FILE:
        raise ScanIncomplete("artifact file exceeds bound")
    expected_format = None
    if path.name.endswith((".tar.gz", ".tgz")):
        expected_format = "tar+gzip"
    elif path.name.endswith(".tar"):
        expected_format = "tar"
    return _scan_bytes(path.read_bytes(), needle, area, path.name, expected_format=expected_format)


def scan_path(path: Path, needle: bytes, area: str) -> list[Finding]:
    if not path.exists():
        raise ScanIncomplete("expected artifact path is absent")
    if path.is_symlink():
        raise ScanIncomplete("artifact path is a symlink")
    files = [path] if path.is_file() else sorted(path.rglob("*"))
    found: list[Finding] = []
    visited = 0
    total_bytes = 0
    for item in files:
        relative = item.relative_to(path) if path.is_dir() else Path(item.name)
        name_bytes = os.fsencode(str(relative))
        if needle in name_bytes:
            found.append(Finding(area, str(relative), "path_name"))
        if item.is_symlink():
            target = os.readlink(item).encode("utf-8", "surrogateescape")
            if needle in target:
                found.append(Finding(area, str(item.relative_to(path)), "symlink_target_or_name"))
            visited += 1
            continue
        if not item.is_file():
            if not item.is_dir():
                raise ScanIncomplete("artifact tree contains unsupported file type")
            continue
        visited += 1
        total_bytes += item.stat().st_size
        if total_bytes > 2 * 1024 * 1024 * 1024:
            raise ScanIncomplete("artifact tree exceeds total scan bound")
        found.extend(scan_file(item, needle, area))
    if not visited:
        raise ScanIncomplete("artifact path contains no files")
    return found


def _digest_hex(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ScanIncomplete("OCI descriptor digest invalid")
    suffix = value.partition(":")[2]
    if len(suffix) != 64 or any(char not in "0123456789abcdef" for char in suffix):
        raise ScanIncomplete("OCI descriptor digest invalid")
    return suffix


def validate_metadata(path: Path) -> list[str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ScanIncomplete("Buildx metadata missing or oversized")
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScanIncomplete("Buildx metadata is not JSON") from error
    if not isinstance(value, dict) or not value:
        raise ScanIncomplete("Buildx metadata object is empty")
    recognized = {"containerimage.digest", "containerimage.config.digest", "containerimage.descriptor", "buildx.build.ref"}
    present = recognized.intersection(value)
    if not present or all(value[key] in (None, "", {}) for key in present):
        raise ScanIncomplete("Buildx metadata lacks recognized build fields")
    return sorted(present)


def validate_local_cache(path: Path) -> dict[str, int]:
    if not path.is_dir() or path.is_symlink():
        raise ScanIncomplete("local cache directory missing")
    layout_path = path / "oci-layout"
    index_path = path / "index.json"
    if any(item.is_symlink() or not item.is_file() or item.stat().st_size > 1024 * 1024 for item in (layout_path, index_path)):
        raise ScanIncomplete("local cache OCI layout or index missing/oversized")
    try:
        layout = json.loads(layout_path.read_bytes())
        index = json.loads(index_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScanIncomplete("local cache OCI layout or index missing/invalid") from error
    if not isinstance(layout, dict) or layout.get("imageLayoutVersion") != "1.0.0":
        raise ScanIncomplete("local cache OCI layout version invalid")
    manifests = index.get("manifests") if isinstance(index, dict) and index.get("schemaVersion") == 2 else None
    if not isinstance(manifests, list) or not manifests:
        raise ScanIncomplete("local cache OCI index has no manifests")
    blob_dir = path / "blobs" / "sha256"
    if not blob_dir.is_dir() or blob_dir.is_symlink():
        raise ScanIncomplete("local cache blob directory missing")
    count = 0
    for blob in blob_dir.iterdir():
        if not blob.is_file() or blob.is_symlink() or blob.stat().st_size > MAX_FILE:
            raise ScanIncomplete("local cache blob invalid or oversized")
        if len(blob.name) != 64 or any(char not in "0123456789abcdef" for char in blob.name):
            raise ScanIncomplete("local cache blob name is not a SHA-256 digest")
        digest = hashlib.sha256()
        with blob.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != blob.name:
            raise ScanIncomplete("local cache blob content hash mismatch")
        count += 1
    if not count:
        raise ScanIncomplete("local cache contains no blobs")
    def blob_target(descriptor: dict) -> Path:
        if not isinstance(descriptor, dict):
            raise ScanIncomplete("local cache descriptor invalid")
        target = blob_dir / _digest_hex(descriptor.get("digest"))
        if not target.is_file():
            raise ScanIncomplete("local cache descriptor target missing")
        return target

    def visit(descriptor: dict, depth: int) -> None:
        if depth > 3:
            raise ScanIncomplete("local cache manifest nesting exceeds bound")
        if descriptor.get("mediaType") not in (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
        ):
            raise ScanIncomplete("local cache index media type invalid")
        try:
            manifest = json.loads(blob_target(descriptor).read_bytes())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScanIncomplete("local cache index target is not JSON") from error
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
            raise ScanIncomplete("local cache manifest schema invalid")
        if "manifests" in manifest:
            children = manifest["manifests"]
            if not isinstance(children, list) or not children:
                raise ScanIncomplete("local cache nested index empty")
            for child in children:
                visit(child, depth + 1)
        else:
            layers = manifest.get("layers")
            if not isinstance(layers, list) or not layers:
                raise ScanIncomplete("local cache manifest layers missing")
            blob_target(manifest.get("config"))
            for layer in layers:
                layer_bytes = blob_target(layer).read_bytes()
                _validate_declared_layer(layer_bytes, layer.get("mediaType"))

    for descriptor in manifests:
        visit(descriptor, 0)
    return {"manifest_count": len(manifests), "blob_count": count}


def oci_history(archive_path: Path, needle: bytes) -> tuple[int, bool]:
    """Follow OCI descriptors to real image configs; reject incomplete layouts."""
    entries = 0
    contains = False
    with tarfile.open(archive_path, mode="r:") as archive:
        members = {member.name.removeprefix("./"): member for member in archive if member.isfile()}

        def read_member(name: str) -> bytes:
            member = members.get(name)
            if member is None or member.size > 16 * 1024 * 1024:
                raise ScanIncomplete("OCI JSON member missing or oversized")
            handle = archive.extractfile(member)
            if handle is None:
                raise ScanIncomplete("OCI member unreadable")
            raw = handle.read(16 * 1024 * 1024 + 1)
            if len(raw) != member.size:
                raise ScanIncomplete("OCI member size mismatch")
            return raw

        def read_json(raw: bytes) -> dict:
            try:
                obj = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ScanIncomplete("OCI descriptor JSON invalid") from error
            if not isinstance(obj, dict):
                raise ScanIncomplete("OCI descriptor JSON is not an object")
            return obj

        def descriptor_bytes(descriptor: dict) -> bytes:
            hex_digest = _digest_hex(descriptor.get("digest"))
            raw = read_member("blobs/sha256/" + hex_digest)
            if hashlib.sha256(raw).hexdigest() != hex_digest:
                raise ScanIncomplete("OCI descriptor blob hash mismatch")
            return raw

        def descriptor_json(descriptor: dict) -> dict:
            return read_json(descriptor_bytes(descriptor))

        def visit_manifest(descriptor: dict, depth: int) -> None:
            nonlocal entries, contains
            if depth > 3:
                raise ScanIncomplete("OCI index nesting exceeds bound")
            obj = descriptor_json(descriptor)
            if obj.get("schemaVersion") != 2:
                raise ScanIncomplete("OCI manifest schema invalid")
            if isinstance(obj.get("manifests"), list):
                for child in obj["manifests"]:
                    if not isinstance(child, dict):
                        raise ScanIncomplete("OCI manifest descriptor invalid")
                    visit_manifest(child, depth + 1)
                return
            config_descriptor = obj.get("config")
            if not isinstance(config_descriptor, dict):
                raise ScanIncomplete("OCI image manifest config missing")
            layers = obj.get("layers")
            if not isinstance(layers, list) or not layers:
                raise ScanIncomplete("OCI image manifest layers missing")
            config_type = config_descriptor.get("mediaType", "")
            for layer in layers:
                if not isinstance(layer, dict):
                    raise ScanIncomplete("OCI image layer descriptor invalid")
                raw_layer = descriptor_bytes(layer)
                if config_type in (
                    "application/vnd.oci.image.config.v1+json",
                    "application/vnd.docker.container.image.v1+json",
                ):
                    _validate_declared_layer(raw_layer, layer.get("mediaType"))
            if config_type not in (
                "application/vnd.oci.image.config.v1+json",
                "application/vnd.docker.container.image.v1+json",
            ):
                return  # Attestation or other non-image artifact.
            config = descriptor_json(config_descriptor)
            history = config.get("history")
            if not isinstance(history, list):
                raise ScanIncomplete("OCI image config history missing")
            for event in history:
                if not isinstance(event, dict):
                    raise ScanIncomplete("invalid OCI history entry")
                created_by = event.get("created_by", "")
                if not isinstance(created_by, str):
                    raise ScanIncomplete("invalid OCI history command")
                entries += 1
                contains = contains or needle in created_by.encode("utf-8")

        index = read_json(read_member("index.json"))
        if index.get("schemaVersion") != 2:
            raise ScanIncomplete("OCI index schema invalid")
        descriptors = index.get("manifests")
        if not isinstance(descriptors, list) or not descriptors:
            raise ScanIncomplete("OCI index manifest list missing")
        for descriptor in descriptors:
            if not isinstance(descriptor, dict):
                raise ScanIncomplete("OCI index descriptor invalid")
            visit_manifest(descriptor, 0)
    if not entries:
        raise ScanIncomplete("OCI export has no image history")
    return entries, contains
