import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path

from build_secret_mount_lifetime_gate.scan import (
    Finding,
    ScanIncomplete,
    oci_history,
    scan_file,
    scan_path,
    validate_local_cache,
    validate_metadata,
)
from build_secret_mount_lifetime_gate.experiment import (
    BuildFailure,
    _buildkit_version,
    _docker_versions,
    _failure_fields,
    _finding_records,
)


MARKER = b"CVP_SYNTHETIC_ONLY_" + b"a" * 64


def tar_with(name: str, payload: bytes) -> bytes:
    return tar_files({name: payload})


def tar_files(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def oci_tar(created_by: str) -> bytes:
    config = json.dumps({"history": [{"created_by": created_by}]}).encode()
    config_digest = hashlib.sha256(config).hexdigest()
    layer = tar_with("ordinary", b"synthetic layer without a marker")
    layer_digest = hashlib.sha256(layer).hexdigest()
    manifest = json.dumps({
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:" + config_digest,
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": "sha256:" + layer_digest,
        }],
    }).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    index = json.dumps({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + manifest_digest}]}).encode()
    return tar_files({
        "index.json": index,
        "blobs/sha256/" + manifest_digest: manifest,
        "blobs/sha256/" + config_digest: config,
        "blobs/sha256/" + layer_digest: layer,
    })


def cache_with_layer(root: Path, layer: bytes, media_type: str) -> None:
    root.mkdir()
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def add_blob(payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        (blobs / digest).write_bytes(payload)
        return "sha256:" + digest

    config_digest = add_blob(b'{"buildkit":"cache-config"}')
    layer_digest = add_blob(layer)
    manifest = json.dumps({
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.buildkit.cacheconfig.v0", "digest": config_digest},
        "layers": [{"mediaType": media_type, "digest": layer_digest}],
    }).encode()
    manifest_digest = add_blob(manifest)
    (root / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest_digest}],
    }))


class ScannerTests(unittest.TestCase):
    def test_nested_oci_layer_marker_is_found(self):
        layer = gzip.compress(tar_with("layer/evidence", MARKER))
        outer = tar_with("blobs/sha256/layer", layer)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.oci.tar"
            path.write_bytes(outer)
            found = scan_file(path, MARKER, "oci_export")
        self.assertTrue(any("!gzip!" in finding.location for finding in found))

    def test_missing_cache_fails_closed_and_symlink_text_is_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ScanIncomplete):
                scan_path(root / "missing", MARKER, "local_cache_export")
            output = root / "output"
            output.mkdir()
            (output / "ordinary").symlink_to("ordinary-target")
            (output / "marker-link").symlink_to(MARKER.decode())
            found = scan_path(output, MARKER, "filesystem_export")
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].representation, "symlink_target_or_name")

    def test_truncated_gzip_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.gz"
            path.write_bytes(gzip.compress(MARKER)[:-4])
            with self.assertRaises(ScanIncomplete):
                scan_file(path, MARKER, "local_cache_export")

    def test_zlib_stream_is_expanded_before_declaring_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache-blob"
            path.write_bytes(zlib.compress(MARKER))
            found = scan_file(path, MARKER, "local_cache_export")
            self.assertTrue(any("!zlib" in item.location for item in found))

    def test_truncated_and_corrupt_tar_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "layer.tar"
            archive = tar_with("normal-member", b"x" * 400)
            for cutoff in (700, 800):
                path.write_bytes(archive[:cutoff])
                with self.assertRaises(ScanIncomplete):
                    scan_file(path, MARKER, "oci_export")
            corrupt = bytearray(archive)
            corrupt[0] ^= 1
            path.write_bytes(corrupt)
            with self.assertRaises(ScanIncomplete):
                scan_file(path, MARKER, "oci_export")

    def test_declared_tar_cache_rejects_damaged_magic_and_checksum(self):
        layer = bytearray(tar_with("payload.zlib", zlib.compress(MARKER)))
        layer[257] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bare_tar = root / "corrupt-magic.tar"
            bare_tar.write_bytes(layer)
            with self.assertRaises(ScanIncomplete):
                scan_file(bare_tar, MARKER, "local_cache_export")
            cache = root / "cache"
            cache_with_layer(cache, bytes(layer), "application/vnd.oci.image.layer.v1.tar")
            with self.assertRaises(ScanIncomplete):
                validate_local_cache(cache)

    def test_declared_oci_image_layer_rejects_damaged_tar(self):
        layer = bytearray(tar_with("payload.zlib", zlib.compress(MARKER)))
        layer[257] ^= 1
        config = json.dumps({"history": [{"created_by": "clean"}]}).encode()
        config_digest = hashlib.sha256(config).hexdigest()
        layer_digest = hashlib.sha256(layer).hexdigest()
        manifest = json.dumps({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + config_digest,
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": "sha256:" + layer_digest,
            }],
        }).encode()
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        index = json.dumps({"schemaVersion": 2, "manifests": [
            {"digest": "sha256:" + manifest_digest}
        ]}).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.oci.tar"
            path.write_bytes(tar_files({
                "index.json": index,
                "blobs/sha256/" + manifest_digest: manifest,
                "blobs/sha256/" + config_digest: config,
                "blobs/sha256/" + layer_digest: bytes(layer),
            }))
            with self.assertRaises(ScanIncomplete):
                oci_history(path, MARKER)

    def test_declared_cache_layer_requires_supported_media_and_matching_gzip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plain = tar_with("clean", b"clean")
            valid = root / "valid"
            cache_with_layer(valid, gzip.compress(plain), "application/vnd.oci.image.layer.v1.tar+gzip")
            self.assertEqual(validate_local_cache(valid), {"manifest_count": 1, "blob_count": 3})

            mislabeled = root / "mislabeled"
            cache_with_layer(mislabeled, plain, "application/vnd.oci.image.layer.v1.tar+gzip")
            with self.assertRaises(ScanIncomplete):
                validate_local_cache(mislabeled)

            unsupported = root / "unsupported"
            cache_with_layer(unsupported, plain, "application/vnd.oci.image.layer.v1.tar+zstd")
            with self.assertRaises(ScanIncomplete):
                validate_local_cache(unsupported)

    def test_regular_file_and_directory_names_are_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            named_dir = root / MARKER.decode()
            named_dir.mkdir()
            (named_dir / "ordinary").write_bytes(b"clean")
            (root / ("file-" + MARKER.decode())).write_bytes(b"clean")
            found = scan_path(root, MARKER, "filesystem_export")
            self.assertGreaterEqual(sum(item.representation == "path_name" for item in found), 2)

    def test_unexpected_zstd_and_zip_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache-blob"
            for magic in (b"\x28\xb5\x2f\xfd", b"PK\x03\x04"):
                path.write_bytes(magic + b"placeholder")
                with self.assertRaises(ScanIncomplete):
                    scan_file(path, MARKER, "local_cache_export")

    def test_failure_log_is_never_persisted_even_when_marker_is_split(self):
        log = MARKER[:46] + b"\n" + MARKER[46:]
        serialized = json.dumps(_failure_fields(BuildFailure("weak Buildx build failed with exit 1", log)))
        self.assertNotIn(MARKER[:46].decode(), serialized)
        self.assertNotIn(MARKER[46:].decode(), serialized)
        self.assertIn("failure_log_sha256", serialized)

    def test_finding_location_is_hashed_when_name_contains_marker(self):
        serialized = json.dumps(_finding_records([Finding("filesystem_export", MARKER.decode(), "path_name")]))
        self.assertNotIn(MARKER.decode(), serialized)
        self.assertIn("location_sha256", serialized)

    def test_metadata_and_cache_placeholders_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.json"
            for payload in (b"", b"{}", b"not JSON"):
                metadata.write_bytes(payload)
                with self.assertRaises(ScanIncomplete):
                    validate_metadata(metadata)
            metadata.write_text('{"buildx.build.ref":"builder/ref"}')
            self.assertEqual(validate_metadata(metadata), ["buildx.build.ref"])

            cache = root / "cache"
            cache.mkdir()
            (cache / "placeholder").write_bytes(b"clean")
            with self.assertRaises(ScanIncomplete):
                validate_local_cache(cache)
            (cache / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
            blob_dir = cache / "blobs" / "sha256"
            blob_dir.mkdir(parents=True)
            def add_blob(payload: bytes) -> str:
                digest = hashlib.sha256(payload).hexdigest()
                (blob_dir / digest).write_bytes(payload)
                return "sha256:" + digest
            config_digest = add_blob(b'{"buildkit":"cache-config"}')
            layer_digest = add_blob(tar_with("cache-entry", b"cache-layer"))
            manifest = json.dumps({"schemaVersion": 2,
                "config": {"digest": config_digest},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer_digest}]}).encode()
            manifest_digest = add_blob(manifest)
            (cache / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest
            }]}))
            self.assertEqual(validate_local_cache(cache), {"manifest_count": 1, "blob_count": 3})

    def test_metadata_known_fields_have_valid_types_and_values(self):
        digest = "sha256:" + "a" * 64
        descriptor = {"digest": digest, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 0}
        valid = [
            {"buildx.build.ref": "builder/ref"},
            {"containerimage.digest": digest},
            {"containerimage.config.digest": digest},
            {"containerimage.descriptor": descriptor},
            {"buildx.build.ref": "builder/ref", "containerimage.digest": digest},
        ]
        invalid = [
            {"buildx.build.ref": []},
            {"buildx.build.ref": "  "},
            {"containerimage.digest": 42},
            {"containerimage.config.digest": "sha256:bad"},
            {"containerimage.descriptor": {"digest": "garbage"}},
            {"containerimage.descriptor": {**descriptor, "size": True}},
            {"containerimage.descriptor": {**descriptor, "size": -1}},
            {"containerimage.descriptor": {**descriptor, "mediaType": ""}},
            {"buildx.build.ref": "builder/ref", "containerimage.digest": 42},
        ]
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            for payload in valid:
                with self.subTest(valid=payload):
                    metadata.write_text(json.dumps(payload))
                    self.assertEqual(validate_metadata(metadata), sorted(payload))
            for payload in invalid:
                with self.subTest(invalid=payload):
                    metadata.write_text(json.dumps(payload))
                    with self.assertRaises(ScanIncomplete):
                        validate_metadata(metadata)

    def test_readable_docker_and_buildkit_versions(self):
        raw = json.dumps({"Client": {"Version": "28.0.4"}, "Server": {
            "Version": "28.0.4", "ApiVersion": "1.48", "Os": "linux", "Arch": "amd64"
        }}).encode()
        self.assertEqual(_docker_versions(raw)["server"], "28.0.4")
        self.assertEqual(_buildkit_version("Nodes:\n  BuildKit: v0.24.0\n"), "v0.24.0")
        self.assertEqual(_buildkit_version("Nodes:\n  BuildKit version:      v0.33.1\n"), "v0.33.1")

    def test_oci_history_positive_control_and_clean_control(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.oci.tar"
            path.write_bytes(oci_tar("ENV COPY=" + MARKER.decode()))
            self.assertEqual(oci_history(path, MARKER), (1, True))
            path.write_bytes(oci_tar("RUN test -n /run/secrets/synthetic_token"))
            self.assertEqual(oci_history(path, MARKER), (1, False))

    def test_oci_history_rejects_unreferenced_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.oci.tar"
            path.write_bytes(tar_with("blobs/sha256/unreferenced", json.dumps({
                "history": [{"created_by": MARKER.decode()}]
            }).encode()))
            with self.assertRaises(ScanIncomplete):
                oci_history(path, MARKER)


if __name__ == "__main__":
    unittest.main()
