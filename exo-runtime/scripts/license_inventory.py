#!/usr/bin/env python3
from __future__ import annotations

import email
import hashlib
import os
import pathlib
import shutil
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


if len(sys.argv) != 3:
    fail("usage: license_inventory.py SITE_PACKAGES OUTPUT")

site = pathlib.Path(sys.argv[1]).resolve(strict=True)
output = pathlib.Path(sys.argv[2])
output.mkdir(parents=True, exist_ok=False)
rows: list[tuple[str, str, str, str]] = []

for metadata_path in sorted(site.glob("*.dist-info/METADATA")):
    with metadata_path.open("r", encoding="utf-8", errors="strict") as handle:
        metadata = email.message_from_file(handle)
    name = metadata.get("Name", "").strip()
    version = metadata.get("Version", "").strip()
    expression = metadata.get("License-Expression", "").strip()
    if not name or not version:
        fail(f"distribution metadata lacks identity: {metadata_path}")
    dist = metadata_path.parent
    candidates: list[pathlib.Path] = []
    license_root = dist / "licenses"
    if license_root.is_dir():
        candidates.extend(path for path in license_root.rglob("*") if path.is_file())
    for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
        candidates.extend(path for path in dist.glob(pattern) if path.is_file())
    unique = sorted(set(candidates))
    if not expression and not unique and not metadata.get_all("License-File", []):
        fail(f"distribution {name} {version} has no license expression or text")
    identity = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    destination = output / f"{identity}-{version}"
    destination.mkdir(mode=0o755)
    text_hashes: list[str] = []
    for index, source in enumerate(unique):
        target = destination / f"{index:03d}-{source.name}"
        shutil.copyfile(source, target)
        target.chmod(0o644)
        text_hashes.append(hashlib.sha256(target.read_bytes()).hexdigest())
    rows.append((name, version, expression or "see-copied-license-files", ",".join(text_hashes)))

if not rows:
    fail("no installed distribution metadata found")

with (output / "PYTHON-DISTRIBUTIONS.tsv").open("w", encoding="utf-8", newline="\n") as handle:
    handle.write("name\tversion\tlicense\tlicense_file_sha256\n")
    for row in sorted(rows, key=lambda item: (item[0].lower(), item[1])):
        handle.write("\t".join(row) + "\n")
os.chmod(output / "PYTHON-DISTRIBUTIONS.tsv", 0o644)

