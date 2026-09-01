#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


if len(sys.argv) != 4:
    fail("usage: rust_license_inventory.py CARGO_METADATA_JSON OUTPUT EXO_LICENSE")

metadata_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
output = pathlib.Path(sys.argv[2])
exo_license = pathlib.Path(sys.argv[3]).resolve(strict=True)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
packages = {package["id"]: package for package in metadata.get("packages", [])}
nodes = {node["id"]: node for node in metadata.get("resolve", {}).get("nodes", [])}
roots = [
    package_id
    for package_id, package in packages.items()
    if package.get("name") == "exo_rs" and pathlib.Path(package["manifest_path"]).name == "Cargo.toml"
]
if len(roots) != 1:
    fail(f"expected one exo-rs Cargo root, found {len(roots)}")

reachable: set[str] = set()
pending = roots[:]
while pending:
    package_id = pending.pop()
    if package_id in reachable:
        continue
    reachable.add(package_id)
    node = nodes.get(package_id)
    if node is None:
        fail(f"resolved Cargo node is absent: {package_id}")
    pending.extend(dependency["pkg"] for dependency in node.get("deps", []))

output.mkdir(parents=True, exist_ok=False)
rows: list[tuple[str, str, str, str, str]] = []
for package_id in sorted(reachable, key=lambda value: (packages[value]["name"].lower(), packages[value]["version"], value)):
    package = packages[package_id]
    name = package["name"]
    version = package["version"]
    expression = (package.get("license") or "").strip()
    source = package.get("source") or "local-exo-rs"
    root = pathlib.Path(package["manifest_path"]).resolve(strict=True).parent
    candidates: list[pathlib.Path] = []
    license_file = package.get("license_file")
    if license_file:
        candidate = pathlib.Path(license_file)
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_file():
            candidates.append(candidate)
    for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
        candidates.extend(path for path in root.glob(pattern) if path.is_file())
    if package.get("source") is None:
        candidates.append(exo_license)
    unique = sorted(set(path.resolve(strict=True) for path in candidates), key=str)
    if not expression and not unique:
        fail(f"Cargo package {name} {version} has no license expression or text")
    identity = "".join(character.lower() if character.isalnum() else "-" for character in name).strip("-")
    destination = output / f"{identity}-{version}"
    destination.mkdir(mode=0o755)
    hashes: list[str] = []
    for index, source_path in enumerate(unique):
        target = destination / f"{index:03d}-{source_path.name}"
        shutil.copyfile(source_path, target)
        target.chmod(0o644)
        hashes.append(hashlib.sha256(target.read_bytes()).hexdigest())
    rows.append((name, version, expression or "see-copied-license-files", source, ",".join(hashes)))

ledger = output / "RUST-DISTRIBUTIONS.tsv"
with ledger.open("w", encoding="utf-8", newline="\n") as handle:
    handle.write("name\tversion\tlicense\tsource\tlicense_file_sha256\n")
    for row in rows:
        handle.write("\t".join(row) + "\n")
os.chmod(ledger, 0o644)
print(f"rust_distributions={len(rows)}")
