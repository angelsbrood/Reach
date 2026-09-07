#!/usr/bin/env python3
"""Offline CPU proof. Keys/context and fake-effect exchange exist only in memory/pipes."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

PRODUCT = Path(__file__).resolve().parent
WIRE_SHA = "2ea861fd3dd7624ca4c8895fb0c917db11cb15ce80d01d1646efea3fc3466007"
GIB = 1 << 30


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class Campaign:
    def __init__(self, repo, test_filter=None, death_group="all"):
        os.umask(0o077)
        self.repo = repo
        self.test_filter = test_filter
        self.death_group = death_group
        self.root = Path(tempfile.mkdtemp(prefix="reach-durable-client-receipts.", dir="/private/tmp"))
        self.private = self.root / "private"
        self.logs = self.root / "logs"
        self.evidence = self.root / "evidence"
        for p in (self.private, self.logs, self.evidence):
            p.mkdir()
        self.fixtures = self.private / "fixtures"
        self.fixtures.mkdir()
        self.package = self.private / "package"
        self.commands = []
        self.children = []
        self.boundaries = []
        self.matrix = []
        self.env = dict(os.environ, S83_FIXTURES=str(self.fixtures),
                        CLANG_MODULE_CACHE_PATH=str(self.private / "clang-cache"),
                        SWIFTPM_MODULECACHE_OVERRIDE=str(self.private / "swift-cache"))
        self.sample()

    def sample(self):
        def allocated(root):
            total = 0
            if root.exists():
                for p in [root, *root.rglob("*")]:
                    try:
                        total += p.lstat().st_blocks * 512
                    except FileNotFoundError:
                        pass  # Compiler temporary roles may disappear during this boundary observation.
            return total
        total = allocated(self.root)
        if PRODUCT.parent.name.startswith("reach-s83."):
            total += allocated(PRODUCT.parent)
        fixtures = allocated(self.fixtures)
        free = shutil.disk_usage(self.root).free
        assert total <= 4 * GIB and fixtures <= GIB and free >= 20 * GIB, "resource ceiling"
        assert all(p.stat().st_size <= 64 << 20 for p in self.logs.rglob("*") if p.is_file()), "log ceiling"
        row = dict(allocated_bytes=total, fixture_bytes=fixtures, free_bytes=free)
        self.boundaries.append(row)
        return row

    def command(self, args, label):
        self.sample()
        start = time.monotonic()
        log = self.logs / (label + ".log")
        with log.open("wb") as output:
            p = subprocess.Popen(args, cwd=self.package, env=self.env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            self.children.append(p)
            while p.poll() is None:
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.sample()
        self.commands.append(dict(label=label, command=args, pid=p.pid, exit_code=p.returncode,
                                  seconds=time.monotonic()-start, log_sha256=sha(log)))
        self.sample()
        assert p.returncode == 0, label + " failed; see bounded log"
        return log.read_text()

    def worker(self, config):
        p = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=self.env, start_new_session=True, bufsize=0)
        self.children.append(p)
        p.stdin.write(json.dumps(config).encode()+b"\n")
        p.stdin.flush()
        return p

    @staticmethod
    def read(p):
        data = bytearray()
        deadline = time.monotonic()+45
        with selectors.DefaultSelector() as select:
            select.register(p.stdout, selectors.EVENT_READ)
            while not data.endswith(b"\n"):
                assert time.monotonic() < deadline and select.select(max(0, deadline-time.monotonic())), "worker reply timeout"
                byte = os.read(p.stdout.fileno(), 1)
                assert byte, "worker closed before reply"
                data.extend(byte)
                assert len(data) <= 4096, "worker output bound"
        return json.loads(data)

    def join(self, p, label, expected=0):
        p.wait(timeout=30)
        assert p.returncode == expected, "worker exit mismatch"
        remainder = p.stdout.read(4097)
        error = p.stderr.read(4097)
        assert not remainder and not error, "unexpected worker output"
        p.stdin.close(); p.stdout.close(); p.stderr.close()
        self.commands.append(dict(label=label, pid=p.pid, exit_code=p.returncode))
        self.sample()

    def request(self, c, label, expected=0):
        p = self.worker(c)
        row = self.read(p)
        self.join(p, label, expected)
        return row

    def config(self, name, action="empty"):
        # Neither this object nor its payload is retained in evidence.
        return dict(path=str(self.fixtures / name), rootID=str(uuid.uuid4()), key=base64.b64encode(os.urandom(32)).decode(),
                    namespace=str(uuid.uuid4()), action=action, boundary="", create=True, time=100, issued=10, expires=100000)

    def deaths(self):
        if self.death_group == "none":
            return
        cases = [
            ("inbox-content", "accept", "afterSnapshot", 0, "absent"),
            ("inbox-prepared", "accept", "beforeManifestRename", 0, "absent"),
            ("inbox-selected", "accept", "afterManifestRename", 4, "unbegun"),
            ("inbox-sync", "accept", "beforeDirectorySync", 4, "unbegun"),
            ("inbox-reply", "accept", "afterInbox", 4, "unbegun"),
            ("before-intent", "begin", "beforeIntent", 4, "unbegun"),
            ("intent-prepared", "begin", "beforeManifestRename", 4, "unbegun"),
            ("intent-selected", "begin", "afterManifestRename", 4, "unknown"),
            ("intent-reply", "begin", "afterIntent", 4, "unknown"),
            ("effect-unknown", "effect", "afterFakeEffect", 4, "unknown"),
            ("outcome-reply", "effect", "afterOutcome", 4, "known"),
        ]
        for label, action, boundary, high, state in (cases if self.death_group == "all" else []):
            c = self.config(label, "empty" if action == "accept" else "setup")
            self.request(c, label+"-setup")
            c.update(create=False, action=action, boundary=boundary)
            p = self.worker(c)
            row = self.read(p)
            effect_count = 0
            if action == "effect":
                assert row == {"signal": "fake-effect"}
                effect_count += 1  # Independent surviving effect. Worker cannot mutate this counter.
                p.stdin.write(b"effect-recorded\n"); p.stdin.flush()
                row = self.read(p)
            assert row == {"signal": boundary}
            p.kill(); self.join(p, label+"-SIGKILL", -signal.SIGKILL)
            c.update(action="inspect", boundary="")
            result = self.request(c, label+"-reopen")
            assert result["high"] == high and result["state"] == state
            if state == "known":
                assert result["exactOutcome"]
                replay = self.request(dict(c, action="accept"), label+"-terminal-replay")
                assert replay["state"] == "known" and replay["exactOutcome"]
            if state in ("unknown", "known"):
                for n in range(2):
                    result = self.request(dict(c, action="retry"), label+f"-repeat-{n}")
                    assert result["state"] == state and result.get("unexpectedFresh") is None
            assert effect_count == (1 if action == "effect" else 0)
            self.matrix.append(dict(case=label, category="actual SIGKILL", boundary=boundary, high=high,
                                    recovered_state=state, independent_effect_count=effect_count,
                                    exact_outcome=state == "known", result="PASS"))
            shutil.rmtree(c["path"])
        for boundary in ("afterRetirement", "duringDeletion", "afterDeletion"):
            c = self.config(boundary, "setup"); self.request(c, boundary+"-setup")
            c.update(create=False, action="maintenance", boundary=boundary, time=c["expires"])
            p = self.worker(c); assert self.read(p) == {"signal": boundary}
            p.kill(); self.join(p, boundary+"-SIGKILL", -signal.SIGKILL)
            result = self.request(dict(c, boundary=""), boundary+"-cleanup")
            assert result == {"expired": True}
            assert sorted(x.name for x in Path(c["path"]).iterdir()) == ["current", "lock"]
            result = self.request(dict(c, action="inspect", boundary=""), boundary+"-expired", expected=1)
            assert result == {"refused": True}
            self.matrix.append(dict(case=boundary, category="actual SIGKILL", original_authority_expired=True,
                                    cleanup_resumed=True, result="PASS"))
            shutil.rmtree(c["path"])
        if self.death_group != "all":
            return
        c = self.config("lock", "setup"); self.request(c, "lock-setup")
        c.update(create=False, action="hold")
        p = self.worker(c); assert self.read(p) == {"signal": "locked"}
        contender = self.request(dict(c, action="inspect"), "lock-contender")
        assert contender == {"busy": True}
        p.kill(); self.join(p, "lock-owner-SIGKILL", -signal.SIGKILL)
        result = self.request(dict(c, action="inspect"), "lock-takeover")
        assert result["state"] == "unbegun"
        self.matrix.append(dict(case="root-lock", category="actual SIGKILL", contender_refused=True,
                                joined_takeover=True, independent_effect_count=0, result="PASS"))
        shutil.rmtree(c["path"])

    def run(self):
        wire = self.repo / "ReachKit/Sources/ReachWire/WireEvent.swift"
        assert sha(wire) == WIRE_SHA, "WireEvent source drift"
        shutil.copytree(PRODUCT, self.package)
        destination = self.package / "Sources/ReachWire"
        destination.mkdir(); shutil.copy2(wire, destination / "WireEvent.swift")
        inputs = {str(p.relative_to(PRODUCT)): sha(p) for p in PRODUCT.rglob("*") if p.is_file()}
        assert len(inputs) == 16, "product path ceiling"
        write_json(self.evidence / "inputs.json", dict(products=inputs, copied_wire_sha256=sha(destination / "WireEvent.swift"),
            source_faithful_bindings={p: sha(self.repo/p) for p in [
                "Tools/ResumableMLXProvider/Sources/ResumableMLXProvider/ProviderEvents.swift",
                "Tools/DurableHostStore/Sources/DurableHostStore/StoreManifest.swift"]}))
        swift = ["/usr/bin/swift"]
        common = ["--disable-sandbox", "--jobs", "4", "--cache-path", str(self.private / "package-cache")]
        self.command(swift + ["build", "--build-tests"] + common, "build")
        bin_path = self.command(swift + ["build", "--show-bin-path"] + common, "bin-path").strip()
        self.binary = Path(bin_path) / "ClientReceiptWorker"
        assert self.binary.is_file() and self.binary.is_relative_to(self.private)
        selection = ["--filter", self.test_filter] if self.test_filter else []
        log = self.command(swift + ["test", "--skip-build"] + common + selection, "tests")
        selected = sorted(re.findall(r"func (test\w+)\(", "\n".join(p.read_text() for p in (PRODUCT/"Tests").rglob("*.swift"))))
        if self.test_filter:
            selected = [name for name in selected if re.search(self.test_filter, name)]
        started = sorted(re.findall(r"Test Case '-\[DurableClientReceiptsTests\.\w+ (test\w+)\]' started", log))
        passed = sorted(re.findall(r"Test Case '-\[DurableClientReceiptsTests\.\w+ (test\w+)\]' passed", log))
        assert selected == started == passed and len(passed) > 0, "test selection mismatch"
        write_json(self.evidence / "tests.json", dict(result="PASS", selected=selected, started=started, passed=passed,
            categories="CPU source-faithful fixtures; injected I/O is separate from actual worker deaths"))
        self.deaths()
        write_json(self.evidence / "matrix.json", self.matrix)
        return dict(result="PASS", tests=len(passed), actual_death_cases=len(self.matrix), worker_sha256=sha(self.binary),
                    claims="Local adapter only; no S82 execution join, native campaign, real effects or receipt consumer")

    def finish(self, result):
        for p in self.children:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=30)
        self.sample()
        assert all(p.poll() is not None for p in self.children)
        shutil.rmtree(self.private)
        write_json(self.evidence / "commands.json", self.commands)
        write_json(self.evidence / "resources.json", dict(
            maximum_allocated_bytes=max(r["allocated_bytes"] for r in self.boundaries),
            maximum_fixture_boundary_bytes=max(r["fixture_bytes"] for r in self.boundaries),
            minimum_free_bytes=min(r["free_bytes"] for r in self.boundaries),
            observation="Explicit launched PIDs and resource boundaries; no exhaustive descendants or continuous RSS claim"))
        result.update(known_owned_pids_joined=[p.pid for p in self.children], private_removed=not self.private.exists(),
                      evidence_sha256={p.name: sha(p) for p in self.evidence.iterdir() if p.is_file()})
        write_json(self.evidence / "results.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PRODUCT.parents[1])
    parser.add_argument("--filter", help="Focused XCTest method regex; unchanged prior evidence may be reused")
    parser.add_argument("--deaths", choices=["all", "retirement", "none"], default="all")
    args = parser.parse_args()
    c = Campaign(args.repo.resolve(), args.filter, args.deaths)
    print(str(c.root), flush=True)
    result = dict(result="FAIL")
    try:
        result = c.run()
    finally:
        c.finish(result)
    print(json.dumps(dict(result=result["result"], tests=result["tests"], actual_death_cases=result["actual_death_cases"],
                          evidence=str(c.evidence))), flush=True)


if __name__ == "__main__":
    main()
