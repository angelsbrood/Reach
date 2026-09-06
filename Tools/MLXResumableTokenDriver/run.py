#!/usr/bin/env python3
"""Offline native check of the local dependency candidate; retain logs, clean owned copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
PINS = {
    "mlx-swift-lm": "83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8",
    "mlx-swift": "0bb916c67f4b9e5c682cbe02a42c701c93ab5021",
    "swift-numerics": "0c0290ff6b24942dadb83a929ffaaa1481df04a2",
    "swift-argument-parser": "6a52f3251125d74daf04fcbd5e6f08a75d074382",
}
METALLIB = "reachd/.build/out/Products/Debug/mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib"
METALLIB_SHA = "684ec284ab6f1f0a4089acfc3f91c1bde801747626c28f69defb65c1193db8a5"
PATCH_PATHS = {
    "Libraries/MLXLMCommon/" + p for p in [
        "Evaluate.swift", "LanguageModel.swift", "KVCache.swift",
        "ResumableTokenDriver.swift", "ResumableTokenCheckpoint.swift",
    ]
} | {"Tests/MLXLMTests/" + p for p in ["ResumableTokenDriverTests.swift", "ResumableTokenCheckpointTests.swift"]}
TEST_SOURCES = ["SampleTests.swift", "KVCacheTests.swift", "MTPDrafterModelTests.swift",
                "ResumableTokenDriverTests.swift", "ResumableTokenCheckpointTests.swift"]
SELECTION = ("ResumableToken|SampleTests|testSimpleCacheRoundTrip|testMTPLastHiddenStatesKeyRoundtrip|"
             "testMTPSharedKVStatesKeyRoundtrip|testMTPEmitFlagKeyDefaultsToFalse|testMTPStateKeysAreDistinct")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def export_git(source, target, revision, records):
    """Export tracked bytes and each already-present pinned submodule, without fetching."""
    if git(source, "rev-parse", "HEAD") != revision or git(source, "status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError(f"source revision/cleanliness mismatch: {source}")
    target.mkdir(parents=True, exist_ok=True)
    archive = target.parent / (target.name + ".tar")
    subprocess.run(["git", "archive", "--format=tar", "--output=" + str(archive), revision], cwd=source, check=True)
    with tarfile.open(archive) as data:
        data.extractall(target, filter="data")
    archive.unlink()
    records[str(source)] = revision
    entries = subprocess.check_output(["git", "ls-tree", "-r", "-z", revision], cwd=source).split(b"\0")
    for entry in entries:
        if entry.startswith(b"160000 "):
            header, relative = entry.decode().split("\t", 1)
            export_git(source / relative, target / relative, header.split()[2], records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reach", type=Path, required=True, help="Reach checkout containing the exact local dependency pins")
    parser.add_argument("--cache-allocation-only", action="store_true",
                        help="Run the seven RC1 allocation/restore checks; reuse prior compatible native-lane and matrix evidence")
    args = parser.parse_args()
    reach = args.reach.resolve()
    candidate = Path(__file__).resolve().parent
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    root = Path(tempfile.mkdtemp(prefix="reach-mlx-resume.", dir="/private/tmp")).resolve()
    private = root / "private"
    logs = root / "logs"
    evidence = root / "evidence"
    for path in (private, logs, evidence):
        path.mkdir(mode=0o700)
    print(f"Evidence: {root}", flush=True)
    commands, observations, source_revisions = [], [], {}
    outcome = {"result": "FAIL", "proof": "native tiny raw-token dependency candidate only"}
    started = time.monotonic()
    env = dict(os.environ)
    for name in ("MLX_SWIFT_BUILD_DOC", "SPI_GENERATE_DOCS"):
        env.pop(name, None)
    env.update(CLANG_MODULE_CACHE_PATH=str(private / "clang-cache"),
               SWIFTPM_MODULECACHE_OVERRIDE=str(private / "swift-cache"),
               XDG_CACHE_HOME=str(private / "xdg-cache"), TMPDIR=str(private / "tmp"),
               PYTHONDONTWRITEBYTECODE="1")
    (private / "tmp").mkdir()
    fixtures = private / "fixtures"
    fixtures.mkdir()

    def resources(label):
        allocated = int(subprocess.check_output(["du", "-sk", str(root)], text=True).split()[0]) * 1024
        fixture_bytes = sum(p.stat().st_size for folder in (fixtures, private / "tmp")
                            for p in folder.rglob("*") if p.is_file())
        free = shutil.disk_usage(root).free
        observations.append({"after": label, "allocated_bytes": allocated,
                             "fixture_bytes": fixture_bytes, "free_bytes": free})
        if allocated > 16 * 1024**3 or fixture_bytes > 64 * 1024**2 or free < 20 * 1024**3:
            raise RuntimeError("S72 resource ceiling/floor")

    def command(label, cmd, cwd, timeout=900):
        t = time.monotonic()
        with (logs / (label + ".log")).open("w") as log:
            process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except BaseException as error:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                if isinstance(error, subprocess.TimeoutExpired):
                    raise RuntimeError(f"timeout: {label}") from None
                raise
        commands.append({"label": label, "command": cmd, "exit_code": code,
                         "seconds": time.monotonic() - t})
        write_json(evidence / "commands.json", commands)
        resources(label)
        if code:
            raise RuntimeError(f"{label} failed with exit {code}; see {logs / (label + '.log')}")
        return (logs / (label + ".log")).read_text()

    try:
        resources("opening")
        developer = subprocess.check_output(["xcode-select", "-p"], text=True).strip()
        swift = subprocess.check_output(["xcrun", "swift", "--version"], text=True, stderr=subprocess.STDOUT)
        if developer != "/Applications/Xcode-beta.app/Contents/Developer" or "swiftlang-6.4.0.33.1" not in swift:
            raise RuntimeError("selected S72 toolchain mismatch; no toolchain upgrade attempted")
        resolved = {p["identity"]: p["state"]["revision"] for p in json.loads((reach / "reachd/Package.resolved").read_text())["pins"]}
        if any(resolved.get(k) != v for k, v in PINS.items()) or sha(reach / METALLIB) != METALLIB_SHA:
            raise RuntimeError("dependency pins or candidate Metal library mismatch")
        write_json(evidence / "inputs.json", {"reach_head": git(reach, "rev-parse", "HEAD"),
            "pins": PINS, "metallib_sha256": METALLIB_SHA, "developer": developer,
            "swift": swift.strip(), "python": sys.version,
            "candidate_sha256": {str(p.relative_to(candidate)): sha(p) for p in candidate.rglob("*") if p.is_file()}})
        harness = private / "harness"
        harness.mkdir()
        for name, revision in PINS.items():
            destination = harness / name if name == "mlx-swift-lm" else private / name
            export_git(reach / "reachd/.build/checkouts" / name, destination, revision, source_revisions)
        write_json(evidence / "source-revisions.json", source_revisions)
        manifest = private / "mlx-swift/Package.swift"
        text = manifest.read_text()
        for name in ("swift-numerics", "swift-argument-parser"):
            original = f'.package(url: "https://github.com/apple/{name}", from: "1.0.0")'
            if text.count(original) != 1:
                raise RuntimeError("local manifest overlay no longer matches pin")
            text = text.replace(original, f'.package(path: "../{name}")')
        manifest.write_text(text)
        build = private / "build"
        flags = ["--package-path", str(harness), "--scratch-path", str(build),
                 "--cache-path", str(private / "spm-cache"), "--config-path", str(private / "spm-config"),
                 "--security-path", str(private / "spm-security"), "--disable-sandbox", "--disable-netrc",
                 "--disable-keychain", "--disable-dependency-cache", "--disable-prefetching",
                 "--skip-update", "--disable-index-store", "--build-system", "native", "--jobs", "4"]
        worker_source = harness / "Sources/CheckpointWorker/main.swift"
        worker_source.parent.mkdir(parents=True)
        (harness / "Package.swift").write_text('''// swift-tools-version: 6.1
import PackageDescription
let package = Package(name: "MLXResumableTokenDriverCandidate", platforms: [.macOS(.v14)],
    products: [.executable(name: "CheckpointWorker", targets: ["CheckpointWorker"])],
    dependencies: [.package(path: "../mlx-swift")], targets: [.executableTarget(name: "CheckpointWorker",
    dependencies: [.product(name: "MLX", package: "mlx-swift"), .product(name: "MLXNN", package: "mlx-swift")])])
''')
        worker_source.write_text('''import MLX
import MLXNN
Device.withDefaultDevice(Device(.gpu)) {
    let value = (MLXArray([Float(1), 2, 3]) * 2).sum()
    eval(value)
    precondition(value.item(Float.self) == 12)
    print("NATIVE_METAL_PASS sum=12")
}
''')
        if not args.cache_allocation_only:
            command("native-build", ["xcrun", "swift", "build", *flags, "--product", "CheckpointWorker"], harness)
        bin_path = Path(subprocess.check_output(["xcrun", "swift", "build", *flags, "--show-bin-path"], cwd=harness, env=env, text=True).strip())
        bin_path.mkdir(parents=True, exist_ok=True)
        binary = bin_path / "CheckpointWorker"
        shutil.copy2(reach / METALLIB, bin_path / "mlx.metallib")
        shutil.copy2(reach / METALLIB, harness / "default.metallib")
        if not args.cache_allocation_only:
            command("native-metal", [str(binary)], harness, 30)
            print("Native MLX/Metal lane PASS", flush=True)
        else:
            outcome["scope"] = "RC1 allocation/restore only; prior compatible native lane and 32 worker pairs are reused, not rerun"
        patch = candidate / "mlx-swift-lm.patch"
        paths = re.findall(r"^diff --git a/(\S+) b/(\S+)$", patch.read_text(), re.M)
        if not paths or any(a != b or a not in PATCH_PATHS for a, b in paths):
            raise RuntimeError("dependency patch path ceiling")
        lm = harness / "mlx-swift-lm"
        command("patch-check", ["git", "apply", "--check", str(patch)], lm, 30)
        command("patch-apply", ["git", "apply", str(patch)], lm, 30)
        write_json(evidence / "patched-source-sha256.json", {a: sha(lm / a) for a, _ in paths})
        for name in ("TinyLlama", "FocusedTests"):
            (harness / name).mkdir()
        for path in ("LLMModel.swift", "Models/Llama.swift"):
            shutil.copy2(lm / "Libraries/MLXLLM" / path, harness / "TinyLlama" / Path(path).name)
        for name in TEST_SOURCES:
            shutil.copy2(lm / "Tests/MLXLMTests" / name, harness / "FocusedTests" / name)
        shutil.copy2(candidate / "Package.swift", harness / "Package.swift")
        shutil.copy2(candidate / "Sources/CheckpointWorker/main.swift", worker_source)
        command("candidate-build", ["xcrun", "swift", "build", *flags, "--build-tests"], harness)
        # xctest may load Cmlx from its private test bundle instead of the executable.
        for bundle in build.rglob("*.xctest"):
            target = bundle / "Contents/MacOS"
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(reach / METALLIB, target / "mlx.metallib")
        selection = ("ResumableTokenCacheAllocationTests|ResumableTokenCheckpointTests|"
                     "testAllBoundariesAndFullStateContinuation|testUnsupportedLogitsRefuseBeforeGPUDispatch") if args.cache_allocation_only else SELECTION
        test_log = command("focused-tests", ["xcrun", "swift", "test", *flags, "--skip-build",
                           "--no-parallel", "--filter", selection], harness, 300)
        expected_tests = 7 if args.cache_allocation_only else 38
        if (f"Executed {expected_tests} tests, with 0 failures" not in test_log
                or (not args.cache_allocation_only and "Test run with 5 tests" not in test_log)):
            raise RuntimeError("focused test count/selection mismatch")
        outcome["test_summary_lines"] = [line.strip() for line in test_log.splitlines()
                                          if "Executed " in line or "Test run with " in line]
        print("Focused native tests PASS", flush=True)
        if args.cache_allocation_only:
            outcome.update(result="PASS", selected_xctest_methods=7, fresh_process_pairs=0,
                           sequential_workers=0, worker_binary_sha256=sha(binary))
        else:
            matrix = []
            for kind in ("llama", "state"):
                for cache in ("simple", "rotating"):
                    for sampling in ("greedy", "stochastic"):
                        for cut in (0, 1, 7, 12):
                            label = f"{kind}-{cache}-{sampling}-{cut}"
                            checkpoint, expected = fixtures / (label + ".checkpoint"), fixtures / (label + ".expected")
                            pair = []
                            for mode in ("produce", "restore"):
                                output = command(label + "-" + mode, [str(binary), mode, kind, cache, sampling,
                                                 str(cut), str(checkpoint), str(expected)], harness, 60)
                                row = json.loads(output)
                                if row["result"] != "PASS" or checkpoint.stat().st_size > 8 * 1024**2:
                                    raise RuntimeError("worker result/checkpoint ceiling")
                                pair.append(row)
                            if pair[0]["pid"] == pair[1]["pid"] or pair[0]["checkpoint_sha256"] != pair[1]["checkpoint_sha256"]:
                                raise RuntimeError("fresh-worker binding")
                            matrix.extend(pair)
                            write_json(evidence / "matrix.json", matrix)
            outcome.update(result="PASS", worker_binary_sha256=sha(binary), fresh_process_pairs=len(matrix)//2,
                           sequential_workers=len(matrix), maximum_checkpoint_bytes=max(x["checkpoint_bytes"] for x in matrix),
                           maximum_mlx_peak_bytes=max(x["mlx_peak_bytes"] for x in matrix),
                           maximum_weight_bytes=max(x["weight_bytes"] for x in matrix))
            print("32 fresh-process continuation pairs PASS", flush=True)
        for source, revision in source_revisions.items():
            if git(source, "rev-parse", "HEAD") != revision or git(source, "status", "--porcelain", "--untracked-files=no"):
                raise RuntimeError("shared dependency source changed during run")
    except Exception as error:
        outcome.update(result="FAIL", error=str(error))
        print(str(error), file=sys.stderr)
    finally:
        outcome["seconds"] = time.monotonic() - started
        outcome["supervision"] = "One build/test command or fixture worker at a time; every owned process joined. On timeout signal its owned process group and join; no claim of exhaustive opaque descendant observation."
        write_json(evidence / "resources.json", {"observations": observations,
            "note": "Boundary observations, not an exhaustively sampled resource peak."})
        shutil.rmtree(private)
        outcome["owned_source_build_fixture_copies_removed"] = not private.exists()
        write_json(evidence / "results.json", outcome)
        print(json.dumps(outcome, indent=2))
    return 0 if outcome["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
