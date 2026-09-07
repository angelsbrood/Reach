#!/usr/bin/env python3
"""Offline real-wire proof. No runtime, dependency fetch, provider or key operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

BASELINE = "95f12615fad636553bf1489322cd86602f9b9b6d"
WIRE = "ReachKit/Sources/ReachWire/"
TESTS = "ReachKit/Tests/ReachWireTests/"
TOOL = "Tools/DurableSessionProtocol/"
OLD_SOURCES = ["Envelope.swift", "Frames.swift", "Wire.swift", "Mirrors.swift", "PortableGeneration.swift", "WireEvent.swift", "FoundationModelsBridge.swift"]
OLD_TESTS = ["FrameCodecTests.swift", "WireTests.swift", "PortableGenerationTests.swift", "GoldenCorpusTests.swift"]
NEW_SOURCES = ["DurableFrames.swift", "DurableNegotiation.swift"]
NEW_TESTS = ["LegacyWireCompatibilityTests.swift", "DurableWireTests.swift"]
GIB = 1 << 30


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def usage(path):
    files = [p for p in path.rglob("*") if p.is_file() and not p.is_symlink()]
    return sum(p.stat().st_size for p in files), len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--overlay", type=Path, help="Private candidate repository-relative files; other inputs come from --repo")
    parser.add_argument("--reuse-baseline", type=Path, help="Prior evidence directory with the same frozen baseline sources and fixture hash")
    parser.add_argument("--filter", help="Focused candidate test selection after an ordinary correction")
    args = parser.parse_args()
    repo = args.repo.resolve()
    root = Path(tempfile.mkdtemp(prefix="reach-s87-protocol.", dir="/private/tmp"))
    evidence = root / "evidence"; evidence.mkdir()
    report = {"baseline_commit": BASELINE, "commands": [], "copied_sources": {}, "skipped": ["GoldenCorpusTests: two historical corpus tests unavailable; excluded, not counted"]}
    print(root, flush=True)

    def source(path):
        if args.overlay and (args.overlay / path).is_file():
            return (args.overlay / path).read_bytes()
        return (repo / path).read_bytes()

    def boundary():
        size, _ = usage(root)
        retained, count = usage(evidence)
        free = shutil.disk_usage(root).free
        # Private overlay is part of task-owned scratch too.
        overlay_size = usage(args.overlay)[0] if args.overlay else 0
        if size + overlay_size > 2 * GIB or retained > 64 << 20 or count > 256 or free < 10 * GIB:
            raise RuntimeError(f"resource ceiling: scratch={size + overlay_size}, retained={retained}/{count}, free={free}")
        return {"scratch_bytes": size + overlay_size, "retained_bytes": retained, "files": count, "free_bytes": free}

    def run(name, argv, cwd, env):
        before = boundary()
        log = evidence / (name + ".log")
        command = {"name": name, "argv": argv, "cwd": str(cwd), "before": before, "deadline_seconds": 600}
        report["commands"].append(command)
        started = time.monotonic()
        with log.open("wb") as output:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            command["pid"] = process.pid
            save(evidence / "report.json", report)
            try:
                while process.poll() is None:
                    if time.monotonic() - started > 600 or log.stat().st_size > 8 << 20:
                        raise RuntimeError("deadline/log ceiling")
                    time.sleep(0.2)
                command["exit_code"] = process.returncode
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                command["joined"] = True
                command["seconds"] = round(time.monotonic() - started, 3)
                command["after"] = boundary()
                command["log_sha256"] = sha(log.read_bytes())
                save(evidence / "report.json", report)
        if log.stat().st_size > 8 << 20 or process.returncode:
            raise RuntimeError(f"{name} failed; retained {log}")

    def git_bytes(path):
        return subprocess.check_output(["git", "show", BASELINE + ":" + path], cwd=repo, timeout=30)

    fixture = source(TESTS + NEW_TESTS[0])
    baseline_sources = {name: git_bytes(WIRE + name) for name in OLD_SOURCES}
    binding = {"commit": BASELINE, "fixture_sha256": sha(fixture), "sources": {name: sha(data) for name, data in baseline_sources.items()}}
    report["baseline_binding"] = binding
    owned = []
    try:
        if args.reuse_baseline:
            prior = json.loads((args.reuse_baseline / "report.json").read_text())
            if prior["baseline_binding"] != binding or not prior.get("baseline_pass"):
                raise RuntimeError("baseline source/fixture binding changed or no prior pass")
            data = (args.reuse_baseline / "baseline-corpus.json").read_bytes()
            if sha(data) != prior["baseline_corpus_sha256"]:
                raise RuntimeError("baseline corpus changed")
            (evidence / "baseline-corpus.json").write_bytes(data)
            report["baseline_reused_from"] = str(args.reuse_baseline.resolve())
            report["baseline_pass"] = True

        for lane in (["candidate"] if args.reuse_baseline else ["baseline", "candidate"]):
            package = root / lane; package.mkdir(); owned.append(package)
            (package / "Package.swift").write_bytes(source(TOOL + "Package.swift"))
            wire = package / "Sources/ReachWire"; wire.mkdir(parents=True)
            tests = package / "Tests/ReachWireTests"; tests.mkdir(parents=True)
            copied = {"Package.swift": sha((package / "Package.swift").read_bytes())}
            for name in OLD_SOURCES + ([] if lane == "baseline" else NEW_SOURCES):
                data = baseline_sources[name] if lane == "baseline" else source(WIRE + name)
                (wire / name).write_bytes(data); copied[WIRE + name] = sha(data)
            names = [NEW_TESTS[0]] if lane == "baseline" else OLD_TESTS + NEW_TESTS
            for name in names:
                data = fixture if name == NEW_TESTS[0] else source(TESTS + name)
                (tests / name).write_bytes(data); copied[TESTS + name] = sha(data)
            report["copied_sources"][lane] = copied
            env = {key: value for key, value in os.environ.items() if key not in ["REACH_WIRE_CORPUS_ROOT", "SWIFT_TESTING_FILTER", "SWIFT_TESTING_SKIP"]}
            env["S87_LEGACY_OUTPUT"] = str(evidence / (lane + "-corpus.json"))
            env["CLANG_MODULE_CACHE_PATH"] = str(package / "module-cache")
            common = ["/usr/bin/xcrun", "swift", "test", "--package-path", str(package), "--scratch-path", str(package / ".build"),
                      "--cache-path", str(package / "cache"), "--config-path", str(package / "config"), "--security-path", str(package / "security"),
                      "--disable-dependency-cache", "--disable-prefetching", "--skip-update", "--disable-netrc", "--disable-keychain",
                      "--disable-index-store", "--disable-sandbox", "--jobs", "4", "--no-parallel"]
            selection = ["--filter", "LegacyWireCompatibilityTests"] if lane == "baseline" else ["--skip", "GoldenCorpusTests"]
            if lane == "candidate" and args.filter:
                selection += ["--filter", args.filter + "|LegacyWireCompatibilityTests"]
            run(lane + "-tests", common + selection, package, env)
            if lane == "baseline":
                report["baseline_pass"] = True
                report["baseline_corpus_sha256"] = sha((evidence / "baseline-corpus.json").read_bytes())
                save(evidence / "report.json", report)
            else:
                run("candidate-test-list", [arg for arg in common if arg != "--no-parallel"] + ["list", "--skip-build"], package, env)
            shutil.rmtree(package); owned.remove(package)

        baseline = (evidence / "baseline-corpus.json").read_bytes()
        candidate = (evidence / "candidate-corpus.json").read_bytes()
        if baseline != candidate:
            raise RuntimeError("legacy exact bytes or invalid categories differ")
        rows = json.loads(candidate)
        report["legacy_rows"] = {prefix: sum(k.startswith(prefix + "/") for k in rows) for prefix in ["valid", "additive", "invalid", "ignored-v0"]}
        report["baseline_corpus_sha256"] = sha(baseline)
        report["candidate_corpus_sha256"] = sha(candidate)
        report["result"] = "PASS: offline protocol/compatibility only"
    except BaseException as error:
        report["result"] = "FAIL: " + str(error)
        raise
    finally:
        for path in owned:
            shutil.rmtree(path)
        report["disposable_sources_and_builds_removed"] = all(not (root / lane).exists() for lane in ["baseline", "candidate"])
        report["final_resources"] = boundary()
        save(evidence / "report.json", report)
        print(report["result"] + " — " + str(evidence / "report.json"), flush=True)


if __name__ == "__main__":
    main()
