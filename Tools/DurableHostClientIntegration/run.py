#!/usr/bin/env python3
"""Offline S84 integration: separate private native-host/CPU-client workers, bounded evidence."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).resolve().parent
S82_RUN_SHA = "29ebccbd15efecb9940b376e12e4270fa68a29cf50caee0e7c4a9f7e77c6e6da"
ACCEPTED_INPUTS_DIGEST = "d3bb4724972bda89f2f93221eb7ba29a3a1fecab12b49e2b20f2c9b658fff03f"
GIB = 1 << 30


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+"\n")


def random_key():
    return base64.b64encode(os.urandom(32)).decode()


class Worker:
    def __init__(self, campaign, binary, config, label):
        self.c = campaign
        self.label = label
        self.log_path = campaign.logs / (label+"-stderr.log")
        self.log = self.log_path.open("wb")
        self.p = subprocess.Popen([str(binary)], cwd=campaign.package, env=campaign.env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.log, start_new_session=True, bufsize=0)
        self.c.children.append(self.p)
        self.send(config)
        self.ready = self.read()

    def send(self, message):
        body = encoded(message)
        replay = "frame" in message
        assert 0 < len(body) <= ((12 if replay else 2) << 20), "IPC message bound"
        for part in (bytes([int(replay)])+struct.pack(">I", len(body)), body):
            remaining = memoryview(part)
            while remaining:
                written = os.write(self.p.stdin.fileno(), remaining[:65536])
                assert written > 0, "closed IPC write"
                remaining = remaining[written:]

    def exact(self, count):
        data = bytearray()
        deadline = time.monotonic()+60
        with selectors.DefaultSelector() as select:
            select.register(self.p.stdout, selectors.EVENT_READ)
            while len(data) < count:
                assert time.monotonic() < deadline and select.select(max(0, deadline-time.monotonic())), "IPC deadline"
                chunk = os.read(self.p.stdout.fileno(), min(65536, count-len(data)))
                assert chunk, "worker closed before reply"
                data.extend(chunk)
        return bytes(data)

    def read(self):
        header = self.exact(5)
        assert header[0] in (0, 1), "IPC class"
        length = struct.unpack(">I", header[1:])[0]
        assert 0 < length <= ((12 if header[0] else 2) << 20), "IPC reply bound"
        body = self.exact(length)
        value = json.loads(body)
        assert encoded(value) == body and ("frame" in value) == bool(header[0]), "IPC canonical class"
        if "peak" in value:
            assert value["peak"] <= 128 << 20
            self.c.mlx_peak = max(self.c.mlx_peak, value["peak"])
        return value

    def request(self, action, **fields):
        self.send(dict(action=action, **fields))
        return self.read()

    def join(self, killed=False, expected=0):
        if killed:
            self.p.kill()
            expected = -signal.SIGKILL
        self.p.wait(timeout=30)
        assert self.p.returncode == expected, "worker exit"
        assert not self.p.stdout.read(4097), "unexpected unconsumed protocol output"
        self.p.stdin.close(); self.p.stdout.close(); self.log.close()
        self.c.commands.append(dict(label=self.label, pid=self.p.pid, exit_code=self.p.returncode,
                                    log_sha256=sha(self.log_path)))
        self.c.sample()

    def close(self):
        assert self.request("close")["action"] == "closed"
        self.join()


class Join:
    """Surviving trusted supervisor. Establishment is marked before worker launch, never inferred from a witness."""
    def __init__(self, campaign, route, label):
        self.c = campaign; self.route = route; self.label = label; self.generation = "g-1"
        self.host_config = dict(action="open", path=str(campaign.fixtures/(label+"-host")), root=str(uuid.uuid4()),
                                key=random_key(), ticketKey=random_key(), time=1_000_000_000, lifetime=86_400_000_000_000)
        self.client_config = dict(action="open", path=str(campaign.fixtures/(label+"-client")), root=str(uuid.uuid4()),
                                  key=random_key(), time=1_000_000_000)
        self.host_established = False; self.client_established = False
        self.host = self.launch_host()
        assert self.host.ready["action"] == "ready"
        result = self.host.request("begin", route=route, generation=self.generation)
        assert result["action"] == "ok" and result.get("context"), "original host context"
        self.authority = result["context"]
        self.client_config["context"] = self.authority
        self.client = self.launch_client()
        self.witness = self.client.ready["witness"]
        self.frames = []; self.effect_count = 0; self.native_calls = 0

    def launch_host(self):
        fresh = not self.host_established
        self.host_established = True
        worker = Worker(self.c, self.c.host_binary, dict(self.host_config, create=fresh), self.label+"-host-"+str(len(self.c.children)))
        if worker.ready["action"] == "ready": self.host_config["ticket"] = worker.ready["ticket"]
        return worker

    def launch_client(self):
        fresh = not self.client_established
        self.client_established = True
        return Worker(self.c, self.c.client_binary, dict(self.client_config, create=fresh), self.label+"-client-"+str(len(self.c.children)))

    def receipt(self, **extra):
        return self.host.request("receipt", witness=self.witness, expectedRoot=self.client_config["root"], generation=self.generation, **extra)

    def attach(self):
        result = self.host.request("attach", generation=self.generation, route=self.route, witness=self.witness,
                                   expectedRoot=self.client_config["root"])
        assert result["action"] == "ok" and result["context"] == self.authority, "original context on host recovery"
        return result

    def drain(self, boundary=""):
        cursor = self.witness["high"]
        self.host.send(dict(action="replay", cursor=cursor))
        return self.receive_frames(cursor, boundary)

    def receive_frames(self, cursor, boundary=""):
        while True:
            response = self.host.read()
            if response["action"] == "replay-end":
                return None
            assert response["action"] == "batch"
            frame = response["frame"]
            self.frames.append(frame)
            reply = self.client.request("accept", frame=frame, cursor=cursor, boundary=boundary)
            if boundary:
                assert reply == dict(action="boundary", boundary=boundary)
                return frame  # Host still waits for its one outstanding frame acknowledgement.
            assert reply["action"] == "ok"
            self.witness = reply["witness"]
            self.host.send(dict(action="next"))

    def public_events(self):
        events = []
        high = 0
        for frame in self.frames:
            assert frame["first"] == high+1 and frame["skip"] == 0, "whole contiguous public output"
            batch = json.loads(base64.b64decode(frame["bytes"], validate=True))
            assert len(batch) == frame["count"]
            events.extend(batch); high += len(batch)
        assert high == self.witness["high"]
        return events

    def validate(self):
        assert self.host.request("validate")["action"] == "ok", "exact native text/call IDs/arguments/usage/terminal"
        assert self.witness["terminal"] and self.native_calls > 0
        assert self.witness["registrations"] == (3 if self.route == "allowed" else 1 if self.route == "required" else 0)
        self.public_events()

    def advance_to_output(self):
        for _ in range(600):
            assert self.receipt()["action"] == "ok"
            response = self.host.request("step")
            assert response["action"] == "ok"
            self.native_calls = max(self.native_calls, response["calls"])
            if response["high"] > 0:
                assert not response["terminal"], "active output boundary"
                return
        raise AssertionError("bounded first publication")

    def drive(self):
        for _ in range(600):
            if self.witness["terminal"]:
                return
            assert self.receipt()["action"] == "ok"
            result = self.host.request("step")
            assert result["action"] == "ok", "actual native step"
            self.native_calls = max(self.native_calls, result["calls"])
            self.drain()
        raise AssertionError("bounded native join")

    def retire(self):
        result = self.receipt()
        assert result["action"] == "ok" and result["phase"] == "tombstone"
        assert result["terminal"] and result["high"] == self.witness["high"]
        self.disposition = result["disposition"]
        assert self.disposition.startswith("durable-receipt-v1:")
        assert not list((Path(self.host_config["path"])/"children").iterdir())
        assert not list((Path(self.host_config["path"])/"requests").iterdir())
        assert self.client.request("witness")["witness"] == self.witness

    def cleanup(self):
        for w in (self.client, self.host):
            if w.p.poll() is None:
                w.close()
        for config in (self.client_config, self.host_config):
            path = Path(config["path"])
            assert path.parent == self.c.fixtures and not path.is_symlink()
            if path.exists():
                shutil.rmtree(path)


class Campaign:
    def __init__(self, repo):
        os.umask(0o077)
        self.repo = repo
        self.root = Path(tempfile.mkdtemp(prefix="reach-durable-host-client-integration.", dir="/private/tmp"))
        self.private = self.root/"private"; self.logs = self.root/"logs"; self.evidence = self.root/"evidence"
        for p in (self.private, self.logs, self.evidence): p.mkdir()
        self.fixtures = self.private/"fixtures"; self.fixtures.mkdir()
        self.package = self.private/"harness"; self.package.mkdir()
        self.commands = []; self.children = []; self.observations = []; self.matrix = []; self.mlx_peak = 0
        self.env = dict(os.environ, S84_FIXTURES=str(self.fixtures), CLANG_MODULE_CACHE_PATH=str(self.private/"clang-cache"),
                        SWIFTPM_MODULECACHE_OVERRIDE=str(self.private/"swift-cache"))
        self.sample()

    def sample(self):
        def allocation(root):
            total = 0
            if root.exists():
                for p in [root, *root.rglob("*")]:
                    try: total += p.lstat().st_blocks*512
                    except FileNotFoundError: pass
            return total
        allocated = allocation(self.root)
        if PRODUCT.parent.name.startswith("reach-s84."): allocated += allocation(PRODUCT.parent)
        fixtures = allocation(self.fixtures); free = shutil.disk_usage(self.root).free
        assert allocated <= 16*GIB and fixtures <= 3*GIB and free >= 20*GIB, "S84 resource ceilings"
        assert all(p.stat().st_size <= 192<<20 for p in self.logs.rglob("*") if p.is_file()), "log bound"
        self.observations.append(dict(allocated_bytes=allocated, fixture_bytes=fixtures, free_bytes=free))

    def command(self, args, label, cwd=None):
        self.sample(); log = self.logs/(label+".log"); started = time.monotonic()
        with log.open("wb") as output:
            p = subprocess.Popen(args, cwd=cwd or self.package, env=self.env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            self.children.append(p)
            while p.poll() is None:
                try: p.wait(timeout=2)
                except subprocess.TimeoutExpired: self.sample()
        self.commands.append(dict(label=label, command=args, pid=p.pid, exit_code=p.returncode,
                                  seconds=time.monotonic()-started, log_sha256=sha(log)))
        self.sample(); assert p.returncode == 0, label+" failed; see bounded log"
        return log.read_text()

    def export(self, source, target, revision, revisions):
        n = str(len(revisions))
        assert self.command(["git", "rev-parse", "HEAD"], "revision-"+n, source).strip() == revision
        assert not self.command(["git", "status", "--porcelain", "--untracked-files=no"], "clean-"+n, source).strip()
        revisions[str(source)] = revision; target.mkdir(parents=True, exist_ok=True)
        assert not any(target.iterdir()), "export target must be empty"
        archive = target.parent/(target.name+".tar")
        self.command(["git", "archive", "--format=tar", "--output="+str(archive), revision], "archive-"+n, source)
        with tarfile.open(archive) as data: data.extractall(target, filter="data")
        archive.unlink()
        tree = self.command(["git", "ls-tree", "-r", revision], "tree-"+n, source)
        for line in tree.splitlines():
            if line.startswith("160000 "):
                header, relative = line.split("\t", 1)
                self.export(source/relative, target/relative, header.split()[2], revisions)

    def prepare(self):
        old = self.repo/"Tools/DurableSessionLifecycle/run.py"
        assert sha(old) == S82_RUN_SHA, "accepted packaging helper"
        legacy = runpy.run_path(str(old))  # Constants only; never invokes an earlier campaign.
        files = {}
        folders = [*legacy["PREREQUISITES"], "DurableSessionLifecycle", "DurableClientReceipts"]
        for folder in folders:
            for p in (self.repo/"Tools"/folder).rglob("*"):
                if p.is_file(): files[str(p.relative_to(self.repo))] = sha(p)
        assert len(files) == 111
        selected = [*legacy["SELECTED_SOURCES"], "ReachKit/Sources/ReachKit/ReachLanguageModel.swift", "ReachKit/Sources/ReachWire/Frames.swift"]
        inputs = dict(files, **{p: sha(self.repo/p) for p in selected})
        assert hashlib.sha256(encoded(inputs)).hexdigest() == ACCEPTED_INPUTS_DIGEST, "accepted products/source drift"
        products = {str(p.relative_to(PRODUCT)): sha(p) for p in PRODUCT.rglob("*") if p.is_file()}
        assert len(products) == 12 and not any(p.is_symlink() for p in PRODUCT.rglob("*")), "twelve-file product ceiling"
        assert sha(self.repo/legacy["METALLIB"]) == legacy["METALLIB_SHA"]
        save(self.evidence/"inputs.json", dict(products=products, accepted_sources=inputs, pins=legacy["PINS"], metallib_sha256=legacy["METALLIB_SHA"]))
        revisions = {}
        for name, revision in legacy["PINS"].items():
            target = self.package/name if name == "mlx-swift-lm" else self.private/name
            self.export(self.repo/"reachd/.build/checkouts"/name, target, revision, revisions)
        manifest = self.private/"mlx-swift/Package.swift"; text = manifest.read_text()
        for name in ("swift-numerics", "swift-argument-parser"):
            original = f'.package(url: "https://github.com/apple/{name}", from: "1.0.0")'
            assert text.count(original) == 1
            text = text.replace(original, f'.package(path: "../{name}")')
        manifest.write_text(text)  # Exact accepted S82 offline manifest overlay.
        lm = self.package/"mlx-swift-lm"
        for n, name in enumerate(legacy["PREREQUISITES"]):
            if "mlx-swift-lm.patch" in legacy["PREREQUISITES"][name]:
                patch = self.repo/"Tools"/name/"mlx-swift-lm.patch"
                self.command(["git", "apply", "--check", str(patch)], f"patch-check-{n}", lm)
                self.command(["git", "apply", str(patch)], f"patch-apply-{n}", lm)
        outputs = {p: sha(lm/p) for p in legacy["PRIOR_OUTPUTS"]}
        assert outputs == legacy["PRIOR_OUTPUTS"] and len(outputs) == 35
        save(self.evidence/"composition.json", dict(revisions=revisions, unchanged_native_outputs=outputs, new_native_outputs=0))
        copied = {}
        for folder, module in [("ResumableRequiredToolCoordinator", "RequiredToolCoordinator"), ("ResumableAllowedToolCoordinator", "AllowedToolCoordinator"),
            ("ResumableMLXProvider", "ResumableMLXProvider"), ("DurableHostStore", "DurableHostStore"),
            ("DurableSessionLifecycle", "DurableSessionLifecycle"), ("DurableSessionLifecycle", "LifecycleFixtures"), ("DurableClientReceipts", "DurableClientReceipts")]:
            for source in (self.repo/"Tools"/folder/"Sources"/module).glob("*.swift"):
                target = self.package/"Sources"/module/source.name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
                assert sha(target) == sha(source); copied[str(target.relative_to(self.package))] = sha(source)
        wire = self.package/"Sources/ReachWire/WireEvent.swift"; wire.parent.mkdir()
        shutil.copy2(self.repo/"ReachKit/Sources/ReachWire/WireEvent.swift", wire); copied[str(wire.relative_to(self.package))] = sha(wire)
        tiny = self.package/"TinyLlama"; tiny.mkdir()
        for p in ("LLMModel.swift", "Models/Llama.swift"): shutil.copy2(lm/"Libraries/MLXLLM"/p, tiny/Path(p).name)
        for name in products:
            if name.startswith(("Sources/", "Tests/")) or name == "Package.swift":
                target = self.package/name; target.parent.mkdir(parents=True, exist_ok=True)
                assert not target.exists(), "no overwrite of accepted copied libraries"
                shutil.copy2(PRODUCT/name, target)
        save(self.evidence/"copied-libraries.json", copied)
        self.flags = ["--package-path", str(self.package), "--scratch-path", str(self.private/"build"), "--cache-path", str(self.private/"spm-cache"),
            "--config-path", str(self.private/"spm-config"), "--security-path", str(self.private/"spm-security"), "--disable-sandbox", "--disable-netrc",
            "--disable-keychain", "--disable-dependency-cache", "--disable-prefetching", "--skip-update", "--disable-index-store", "--build-system", "native", "--jobs", "4"]
        output = self.command(["xcrun", "swift", "build", *self.flags, "--show-bin-path"], "binary-path")
        paths = [p for p in output.splitlines() if p.startswith(str(self.private/"build")+"/")]; assert len(paths) == 1
        binary = Path(paths[0]); binary.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.repo/legacy["METALLIB"], binary/"mlx.metallib")
        shutil.copy2(self.repo/legacy["METALLIB"], self.package/"default.metallib")
        self.command(["xcrun", "swift", "build", *self.flags, "--build-tests"], "build")
        for bundle in (self.private/"build").rglob("*.xctest"):
            target = bundle/"Contents/MacOS"; target.mkdir(parents=True, exist_ok=True); shutil.copy2(self.repo/legacy["METALLIB"], target/"mlx.metallib")
        self.host_binary = binary/"HostWorker"; self.client_binary = binary/"ClientWorker"
        symbols = self.command(["nm", "-u", str(self.client_binary)], "client-symbols")
        assert not re.search(r"(?i)(mlx_|cmlx|metal)", symbols), "CPU-only client symbol boundary"
        self.accepted_inputs = inputs; self.copied = copied; self.outputs = outputs; self.revisions = revisions

    def tests(self, pattern=None):
        extra = ["--filter", pattern] if pattern else []
        log = self.command(["xcrun", "swift", "test", *self.flags, "--skip-build", "--no-parallel", *extra], "tests")
        log = re.sub(r"warning: '--build-system native'[^\n]*\n", "", log)
        selected = sorted(re.findall(r"func (test\w+)\(", "\n".join(p.read_text() for p in (PRODUCT/"Tests").rglob("*.swift"))))
        if pattern: selected = [name for name in selected if re.search(pattern, name)]
        started = sorted(re.findall(r"Test Case '-\[HostClientIntegrationTests\.\w+ (test\w+)\]' started", log))
        passed = sorted(re.findall(r"Test Case '-\[HostClientIntegrationTests\.\w+ (test\w+)\]' passed", log))
        assert selected == started == passed and passed
        save(self.evidence/"tests.json", dict(result="PASS", filter=pattern, selected=selected, started=started, passed=passed))
        return len(passed)

    def workers(self, pattern=None):
        selected = lambda label: not pattern or re.search(pattern, label) is not None
        reference = None
        for route in ("ordinary", "guided", "required", "allowed"):
            if not selected("route-"+route) and not (route == "ordinary" and selected("active-native-restore")): continue
            join = Join(self, route, "route-"+route)
            try:
                join.drive(); join.validate()
                if route == "ordinary": reference = join.public_events()
                join.retire()
                if route in ("required", "allowed"):
                    assert join.client.request("state")["state"] == "unbegun", "host retirement preserves pending calls"
                self.matrix.append(dict(case="route-"+route, native_calls=join.native_calls,
                    registrations=join.witness["registrations"], exact_output=True, retired=True))
                if route == "guided":
                    # A second actual generation shares the original namespace, roots, keys and ticket.
                    original = json.loads(base64.b64decode(join.authority)); first_authority = join.authority
                    first_witness = join.witness; first_disposition = join.disposition
                    join.client.close(); join.generation = "g-2"
                    response = join.host.request("begin", route=route, generation=join.generation)
                    assert response["action"] == "ok"
                    join.authority = response["context"]
                    second = json.loads(base64.b64decode(join.authority))
                    for field in ("caller", "host", "store", "namespace", "issued", "expires"):
                        assert second[field] == original[field], "same original namespace authority"
                    assert second["upstreamDigest"] != original["upstreamDigest"] and second["generation"] != original["generation"]
                    join.client_config["context"] = join.authority
                    join.client = join.launch_client(); join.witness = join.client.ready["witness"]
                    assert join.witness["high"] == 0
                    join.frames = []; join.native_calls = 0
                    join.drive(); join.validate(); join.retire()
                    join.client.close(); join.client_config["context"] = first_authority
                    join.client = join.launch_client()
                    assert join.client.ready["witness"] == first_witness, "prior generation receipt remains intact"
                    response = join.host.request("receipt", generation="g-1", witness=first_witness,
                        expectedRoot=join.client_config["root"])
                    assert response["action"] == "ok" and response["disposition"] == first_disposition
                    self.matrix.append(dict(case="same-namespace-multiple-generations", generations=2,
                        stable_original_authority=True, prior_receipt_preserved=True))
            finally: join.cleanup()

        if selected("active-native-restore"):
            join = Join(self, "ordinary", "active-native-restore")
            try:
                join.advance_to_output(); join.drain()
                frontier = join.witness["high"]; assert frontier > 0 and not join.witness["terminal"]
                assert join.receipt()["action"] == "ok"
                assert join.host.request("step", boundary="afterStep") == dict(action="boundary", boundary="afterStep")
                join.host.join(killed=True); join.host = join.launch_host(); join.native_calls = 0
                join.attach(); join.drain(); join.drive(); join.validate()
                assert join.native_calls > 0, "actual new native calls after active host recovery"
                output = join.public_events()
                assert output[:frontier] == reference[:frontier] and output[frontier:] == reference[frontier:], "exact public suffix after new native calls"
                join.retire()
                self.matrix.append(dict(case="active-native-restore", death="afterStep", durable_frontier=frontier,
                    new_native_calls=join.native_calls, exact_public_suffix=True))
            finally: join.cleanup()

        for boundary in ("beforeManifestRename", "afterWitness"):
            if not selected("inbox-"+boundary): continue
            join = Join(self, "ordinary", "inbox-"+boundary)
            try:
                join.advance_to_output(); original = join.witness
                frame = join.drain(boundary=boundary)
                join.client.join(killed=True); join.client = join.launch_client()
                recovered = join.client.ready["witness"]
                if boundary == "beforeManifestRename": assert recovered == original
                else: assert recovered["high"] == frame["first"]+frame["count"]-1
                # Replay the exact outstanding full frame; only selected bytes can advance the frontier.
                reply = join.client.request("accept", frame=frame, cursor=original["high"])
                assert reply["action"] == "ok"
                if boundary == "afterWitness": assert reply["witness"] == recovered
                join.witness = reply["witness"]
                for field in ("bytes", "commit"):
                    changed = dict(frame)
                    changed[field] = base64.b64encode(b"[]").decode() if field == "bytes" else ("a" if frame[field][0] != "a" else "b")+frame[field][1:]
                    assert join.client.request("accept", frame=changed, cursor=original["high"])["action"] == "refused"
                    assert join.client.request("witness")["witness"] == join.witness
                join.host.send(dict(action="next")); join.receive_frames(original["high"])
                join.drive(); join.validate(); join.retire()
                self.matrix.append(dict(case="inbox-"+boundary, death=boundary,
                    recovered_committed=boundary == "afterWitness", exact_replay=True, changed_bytes_commit_refused=True))
            finally: join.cleanup()

        for boundary in ("beforeRetirementIntent", "afterRetirementIntent", "duringContentDeletion", "afterTombstone"):
            if not selected("receipt-"+boundary): continue
            join = Join(self, "required", "receipt-"+boundary)
            try:
                join.drive(); join.validate()
                assert join.receipt(boundary=boundary) == dict(action="boundary", boundary=boundary)
                join.host.join(killed=True); join.host = join.launch_host()
                if boundary == "beforeRetirementIntent": join.attach()
                response = join.receipt()
                assert response["action"] == "ok" and response["phase"] == "tombstone"
                assert response["calls"] == 0 and response["factories"] == 0, "retirement retry cannot launch provider"
                disposition = response["disposition"]; join.retire()
                assert join.disposition == disposition
                changed = dict(join.witness, revision=join.witness["revision"]+1)
                response = join.host.request("receipt", generation=join.generation, witness=changed,
                    expectedRoot=join.client_config["root"])
                assert response["action"] == "refused" and join.receipt()["disposition"] == disposition
                assert join.client.request("state")["state"] == "unbegun"
                self.matrix.append(dict(case="receipt-"+boundary, death=boundary, exact_retry=True,
                    changed_receipt_refused=True, retry_native_calls=0, retry_provider_factories=0))
            finally: join.cleanup()

        for boundary, expected_count, state in (("afterIntent", 0, "unknown"), ("afterFakeEffect", 1, "unknown"), ("afterOutcome", 1, "known")):
            if not selected("effect-"+boundary): continue
            join = Join(self, "required", "effect-"+boundary)
            try:
                join.drive(); join.validate(); join.retire()
                reply = join.client.request("effect", boundary=boundary)
                if expected_count:
                    assert reply["action"] == "fake-effect"
                    join.effect_count += 1  # Survives the client and is never inferred from its journal.
                    join.client.send(dict(action="effect-recorded")); reply = join.client.read()
                assert reply == dict(action="boundary", boundary=boundary)
                join.client.join(killed=True); join.client = join.launch_client()
                assert join.client.ready["witness"] == join.witness
                for action in ("state", "begin", "effect", "begin"):
                    reply = join.client.request(action)
                    assert reply["action"] == "ok" and reply["state"] == state, "no repeated effect permission"
                    if state == "known": assert base64.b64decode(reply["result"]) == b"s84-known-result"
                assert join.effect_count == expected_count
                assert join.client.request("witness")["witness"] == join.witness
                assert join.receipt()["disposition"] == join.disposition, "effects leave receipt identity unchanged"
                if state == "known":
                    expiry = json.loads(base64.b64decode(join.authority))["expires"]
                    assert join.client.request("witness", time=expiry-1)["witness"] == join.witness
                    assert join.client.request("state")["state"] == "known"
                    assert join.client.request("maintenance", time=expiry)["action"] == "ok"
                    assert join.client.request("state")["action"] == "refused"
                    assert join.receipt()["disposition"] == join.disposition
                    assert join.host.request("maintenance", time=expiry)["action"] == "ok"
                    assert join.receipt()["action"] == "refused", "original ticket cannot revive removed tombstone"
                self.matrix.append(dict(case="effect-"+boundary, death=boundary, effect_count=join.effect_count,
                    recovered_state=state, repeated_permission=False, exact_known_bytes=state == "known", host_already_retired=True,
                    independent_original_expiry_checked=state == "known"))
            finally: join.cleanup()

        for role in ("client", "host"):
            if not selected("missing-established-"+role): continue
            join = Join(self, "ordinary", "missing-established-"+role)
            try:
                worker = getattr(join, role); config = getattr(join, role+"_config")
                worker.close(); path = Path(config["path"]); shutil.rmtree(path)
                assert getattr(join, role+"_established"), "supervisor establishment predates launch"
                worker = getattr(join, "launch_"+role)()
                setattr(join, role, worker)
                assert worker.ready["action"] == "unavailable" and not path.exists(), "no silent established-root recreation"
                worker.join(expected=1)
                self.matrix.append(dict(case="missing-established-"+role, fresh_launch_forbidden=True,
                    original_configuration_retained=True, journal_recreated=False))
            finally: join.cleanup()

    def verify_inputs(self):
        for p, h in self.accepted_inputs.items(): assert sha(self.repo/p) == h
        for p, h in self.copied.items(): assert sha(self.package/p) == h
        assert {p: sha(self.package/"mlx-swift-lm"/p) for p in self.outputs} == self.outputs
        for n, (source, revision) in enumerate(self.revisions.items()):
            assert self.command(["git", "rev-parse", "HEAD"], "final-revision-"+str(n), source).strip() == revision
            assert not self.command(["git", "status", "--porcelain", "--untracked-files=no"], "final-clean-"+str(n), source).strip()

    def finish(self, result):
        for p in self.children:
            if p.poll() is None: os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=30)
        self.sample(); assert all(p.poll() is not None for p in self.children)
        shutil.rmtree(self.private)
        save(self.evidence/"matrix.json", self.matrix)
        save(self.evidence/"commands.json", self.commands)
        save(self.evidence/"resources.json", dict(maximum_allocated_bytes=max(x["allocated_bytes"] for x in self.observations),
            maximum_fixture_boundary_bytes=max(x["fixture_bytes"] for x in self.observations), minimum_free_bytes=min(x["free_bytes"] for x in self.observations),
            mlx_peak_bytes=self.mlx_peak, observation="Explicit launched children and allocation boundaries; no continuous RSS or exhaustive opaque-descendant claim"))
        result.update(owned_child_pids_joined=[p.pid for p in self.children], private_removed=True,
                      evidence_sha256={p.name: sha(p) for p in self.evidence.iterdir() if p.is_file()})
        save(self.evidence/"results.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PRODUCT.parents[1])
    parser.add_argument("--tests-only", action="store_true", help="Focused source/contract tests; does not claim worker campaign")
    parser.add_argument("--test-filter", help="Run only matching test method names; unchanged evidence must be reused explicitly")
    parser.add_argument("--workers-only", action="store_true", help="Reuse unchanged XCTest evidence; build and execute workers only")
    parser.add_argument("--worker-filter", help="Run matching case labels plus the ordinary reference required by active recovery")
    args = parser.parse_args(); c = Campaign(args.repo.resolve()); print(c.root, flush=True)
    result = dict(result="FAIL")
    try:
        assert not (args.tests_only and args.workers_only)
        c.prepare(); count = 0 if args.workers_only else c.tests(args.test_filter)
        if not args.tests_only: c.workers(args.worker_filter)
        c.verify_inputs()
        result = dict(result="PASS", tests=count, tests_executed=not args.workers_only,
                      worker_cases=len(c.matrix), matrix_executed=not args.tests_only, worker_filter=args.worker_filter,
                      host_binary_sha256=sha(c.host_binary), client_binary_sha256=sha(c.client_binary))
        save(c.evidence/"matrix.json", c.matrix)
    finally:
        c.finish(result)
    print(json.dumps(dict(result=result["result"], tests=result["tests"], worker_cases=result["worker_cases"], evidence=str(c.evidence))), flush=True)


if __name__ == "__main__": main()
