"""Run an A/B BuildKit experiment using a fresh synthetic marker only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .scan import Finding, ScanIncomplete, oci_history, scan_path, validate_local_cache, validate_metadata


PROJECT = "BuildSecretMountLifetimeGate"
SOURCE = Path(__file__).resolve().parent / "fixtures"
BASE_IMAGE = "alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"
FRONTEND = "docker/dockerfile:1.7.0@sha256:dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56"


class BuildFailure(Exception):
    def __init__(self, message: str, log: bytes | None = None):
        super().__init__(message)
        self.log = log


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _failure_fields(error: BuildFailure) -> dict[str, str]:
    fields = {"failure": str(error)}
    if error.log is not None:
        fields["failure_log_sha256"] = _sha(error.log)
    return fields


def _docker_versions(raw: bytes) -> dict[str, str]:
    try:
        value = json.loads(raw)
        client = value["Client"]
        server = value["Server"]
        versions = {
            "client": client["Version"],
            "server": server["Version"],
            "server_api": server["ApiVersion"],
            "server_os": server["Os"],
            "server_arch": server["Arch"],
        }
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScanIncomplete("Docker client/server version JSON invalid") from error
    if any(not isinstance(item, str) or not item for item in versions.values()):
        raise ScanIncomplete("Docker client/server version fields incomplete")
    return versions


def _buildkit_version(inspect: str) -> str:
    found = re.search(r"(?m)^\s*BuildKit(?: version)?:\s*(v?[0-9]+\.[0-9]+\.[0-9]+[^\s]*)\s*$", inspect)
    if not found:
        raise ScanIncomplete("BuildKit version not found in builder inspection")
    return found.group(1)


def _run_plain(argv: list[str]) -> bytes:
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise BuildFailure(f"preflight command failed with exit {completed.returncode}", completed.stdout)
    return completed.stdout


def _finding_records(findings: list[Finding]) -> list[dict[str, str]]:
    return [
        {
            "area": item.area,
            "location_sha256": _sha(item.location.encode("utf-8", "surrogatepass")),
            "representation": item.representation,
        }
        for item in findings
    ]


def _build(
    builder: str,
    branch: str,
    raw_root: Path,
    secret: bytes,
    expected_sha256: str,
) -> bytes:
    dest = raw_root / branch
    dest.mkdir(parents=True, exist_ok=False)
    dockerfile = SOURCE / f"{branch}.Dockerfile"
    command = [
        "docker", "buildx", "build", "--builder", builder,
        "--no-cache", "--progress=plain", "--platform", "linux/amd64",
        "--file", str(dockerfile),
        "--output", f"type=oci,dest={dest / 'image.oci.tar'},compression=gzip",
        "--output", f"type=local,dest={dest / 'filesystem'}",
        "--cache-to", f"type=local,dest={dest / 'cache'},mode=max,compression=gzip",
        "--metadata-file", str(dest / "metadata.json"),
    ]
    env = os.environ.copy()
    if branch == "weak":
        # Docker reads this ARG from the child process environment. The value
        # never appears in the command-line arguments or this repository.
        env["SYNTHETIC_SECRET"] = secret.decode("ascii")
        command.extend(["--build-arg", "SYNTHETIC_SECRET"])
    else:
        env.pop("SYNTHETIC_SECRET", None)
        command.extend([
            "--build-arg", f"EXPECTED_SHA256={expected_sha256}",
            "--secret", f"id=synthetic_token,src={raw_root / 'synthetic-token'}",
        ])
    command.append(str(SOURCE))
    completed = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise BuildFailure(f"{branch} Buildx build failed with exit {completed.returncode}", completed.stdout)
    return completed.stdout


def _inspect_branch(
    branch: str, raw_root: Path, marker: bytes, log: bytes
) -> dict[str, object]:
    dest = raw_root / branch
    metadata_keys = validate_metadata(dest / "metadata.json")
    cache_structure = validate_local_cache(dest / "cache")
    areas = {
        "oci_export": scan_path(dest / "image.oci.tar", marker, "oci_export"),
        "filesystem_export": scan_path(dest / "filesystem", marker, "filesystem_export"),
        "local_cache_export": scan_path(dest / "cache", marker, "local_cache_export"),
        "build_metadata": scan_path(dest / "metadata.json", marker, "build_metadata"),
        "build_log": [] if marker not in log else [Finding("build_log", "captured_stdout", "literal")],
    }
    history_count, history_has_marker = oci_history(dest / "image.oci.tar", marker)
    return {
        "history_entry_count": history_count,
        "marker_in_image_history": history_has_marker,
        "build_log_sha256": _sha(log),
        "metadata_keys": metadata_keys,
        "cache_structure": cache_structure,
        "areas": {
            name: {"marker_found": bool(findings), "findings": _finding_records(findings)}
            for name, findings in areas.items()
        },
    }


def execute(build_root: Path) -> tuple[Path, dict[str, object]]:
    if build_root.name != "Build":
        raise ValueError("build root must be a directory named Build")
    if not shutil.which("docker"):
        raise BuildFailure("Docker is unavailable; real BuildKit experiment remains OPEN")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    run_root = build_root / "验证" / f"{PROJECT}-{run_id}"
    raw_parent = build_root / f"{PROJECT}-raw"
    raw_root = raw_parent / f"{PROJECT}-{run_id}"
    run_root.parent.mkdir(parents=True, exist_ok=True)
    if raw_parent.is_symlink():
        raise BuildFailure("private raw output parent is a symlink")
    raw_parent.mkdir(mode=0o700, exist_ok=True)
    raw_parent.chmod(0o700)
    run_root.mkdir(mode=0o700, exist_ok=False)
    raw_root.mkdir(mode=0o700, exist_ok=False)
    run_root.chmod(0o700)
    raw_root.chmod(0o700)
    if stat.S_IMODE(run_root.stat().st_mode) != 0o700 or stat.S_IMODE(raw_root.stat().st_mode) != 0o700:
        raise BuildFailure("private experiment directory permissions could not be established")
    marker = b"CVP_SYNTHETIC_ONLY_" + secrets.token_hex(32).encode("ascii")
    marker_sha256 = _sha(marker)
    secret_path = raw_root / "synthetic-token"
    builder = "bsmg-" + secrets.token_hex(5)
    receipt: dict[str, object] = {
        "schema": 1,
        "project": PROJECT,
        "version": __version__,
        "status": "FAIL",
        "run_id": run_id,
        "synthetic_marker_sha256": marker_sha256,
        "synthetic_marker_length": len(marker),
        "base_image": BASE_IMAGE,
        "dockerfile_frontend": FRONTEND,
        "dockerfile_sha256": {
            branch: _sha((SOURCE / f"{branch}.Dockerfile").read_bytes())
            for branch in ("weak", "secure")
        },
        "runner_image": os.environ.get("ImageOS", "unknown"),
        "runner_image_version": os.environ.get("ImageVersion", "unknown"),
        "github_sha": os.environ.get("GITHUB_SHA", "local-unbound"),
        "raw_outputs_removed": False,
        "run_root_mode": oct(stat.S_IMODE(run_root.stat().st_mode)),
        "raw_root_mode_before_cleanup": oct(stat.S_IMODE(raw_root.stat().st_mode)),
        "limitations": [
            "Selected owner-controlled Dockerfiles, exact base/frontend, builder, cache exporter and run only.",
            "Secret bytes do not form a BuildKit cache key; each branch uses --no-cache and a distinct cache directory.",
            "Secret mount does not prevent a build instruction from deliberately copying, printing or deriving the value.",
            "This does not establish a BuildKit vulnerability, general non-leakage or CVP eligibility.",
        ],
    }
    builder_created = False
    try:
        descriptor = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as secret_file:
            secret_file.write(marker)
        docker_version_raw = _run_plain(["docker", "version", "--format", "{{json .}}"])
        receipt["docker_version_sha256"] = _sha(docker_version_raw)
        receipt["docker_versions"] = _docker_versions(docker_version_raw)
        receipt["buildx_version"] = _run_plain(["docker", "buildx", "version"]).decode("utf-8", "replace").strip()
        _run_plain(["docker", "buildx", "create", "--driver", "docker-container", "--name", builder])
        builder_created = True
        receipt["builder_inspect"] = _run_plain(["docker", "buildx", "inspect", builder, "--bootstrap"]).decode("utf-8", "replace")
        receipt["buildkit_version"] = _buildkit_version(receipt["builder_inspect"])
        results: dict[str, object] = {}
        for branch in ("weak", "secure"):
            log = _build(builder, branch, raw_root, marker, marker_sha256)
            results[branch] = _inspect_branch(branch, raw_root, marker, log)
        receipt["branches"] = results
        weak = results["weak"]
        secure = results["secure"]
        assert isinstance(weak, dict) and isinstance(secure, dict)
        assert isinstance(secure.get("areas"), dict)
        assert isinstance(weak.get("areas"), dict)
        weak_ok = bool(weak["marker_in_image_history"]) and bool(
            weak["areas"]["oci_export"]["marker_found"]
        )
        secure_ok = not secure["marker_in_image_history"] and all(
            not area["marker_found"] for area in secure["areas"].values()
        )
        receipt["weak_history_positive_control"] = weak_ok
        receipt["secure_export_absence_control"] = secure_ok
        receipt["status"] = "PASS" if weak_ok and secure_ok else "FAIL"
        if not weak_ok:
            receipt["failure"] = "weak OCI image/history did not retain the synthetic marker"
        elif not secure_ok:
            receipt["failure"] = "secure branch retained the synthetic marker"
    except (BuildFailure, ScanIncomplete, OSError, ValueError) as error:
        if isinstance(error, BuildFailure):
            receipt.update(_failure_fields(error))
        elif isinstance(error, ScanIncomplete):
            receipt["failure"] = str(error)
        else:
            receipt["failure"] = "local file or value operation failed"
    finally:
        if builder_created:
            try:
                completed = subprocess.run(
                    ["docker", "buildx", "rm", builder],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                receipt["builder_removed"] = completed.returncode == 0
                if completed.returncode:
                    receipt["builder_cleanup_log_sha256"] = _sha(completed.stdout)
            except OSError:
                receipt["builder_removed"] = False
            if not receipt["builder_removed"]:
                receipt["status"] = "FAIL"
                receipt["failure"] = "disposable Buildx builder cleanup failed"
        secret_path.unlink(missing_ok=True)
        shutil.rmtree(raw_root, ignore_errors=False)
        receipt["raw_outputs_removed"] = True
        receipt_path = run_root / "receipt.json"
        encoded = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        if marker in encoded:
            raise RuntimeError("receipt unexpectedly contains synthetic marker")
        receipt_path.write_bytes(encoded + b"\n")
    return receipt_path, receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt_path, receipt = execute(args.build_root.resolve())
    except (BuildFailure, ValueError) as error:
        print(f"OPEN: {error}", file=sys.stderr)
        return 2
    print(f"{receipt['status']}: sanitized receipt at {receipt_path}")
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
