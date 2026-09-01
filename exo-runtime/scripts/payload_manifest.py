#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import pathlib
import stat
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: payload_manifest.py ROOT OUTPUT")

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
output = pathlib.Path(sys.argv[2])
rows: list[str] = []

def append_path(path: pathlib.Path) -> None:
    relative = path.relative_to(root).as_posix()
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        kind = "symlink"
        value = os.readlink(path)
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        size = len(value.encode("utf-8"))
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        size = info.st_size
    else:
        raise SystemExit(f"unsupported payload object: {path}")
    rows.append(f"{kind}\t{mode:04o}\t{size}\t{digest}\t{relative}")


for directory, names, files in os.walk(root, topdown=True, followlinks=False):
    names.sort()
    files.sort()
    base = pathlib.Path(directory)
    for name in tuple(names):
        path = base / name
        if path.is_symlink():
            append_path(path)
            names.remove(name)
    for name in files:
        append_path(base / name)

output.write_text("kind\tmode\tbytes\tsha256\tpath\n" + "\n".join(rows) + "\n", encoding="utf-8", newline="\n")
output.chmod(0o644)
