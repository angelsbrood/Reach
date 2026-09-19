#!/usr/bin/env python3
"""Explicit local S106 qualification. No installation, discovery, or issuer persistence.

Run feasibility first, then campaign with its successful result. Every runtime child
uses the same literal-endpoint sandbox. Compiler supervision is deliberately separate.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import traceback
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Child:
    def __init__(self, run, name, endpoint, arguments):
        self.run, self.name = run, name
        self.directory = run.output / name
        self.directory.mkdir(mode=0o700)
        profile = run.profile(endpoint)
        (self.directory / "sandbox.sb").write_text(profile)
        command = ["/usr/bin/sandbox-exec", "-p", profile, str(run.executable), *arguments]
        self.output = (self.directory / "stdout.log").open("xb")
        self.errors = (self.directory / "stderr.log").open("xb")
        self.started = time.monotonic()
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.errors)
        self.buffer, self.events, self.joined = b"", [], False
        self.record = dict(name=name, pid=self.process.pid, command=command, events=self.events)
        run.children.append(self)
        run.sample()

    def pump(self, timeout):
        if select.select([self.process.stdout], [], [], timeout)[0]:
            data = os.read(self.process.stdout.fileno(), 65536)
            self.output.write(data)
            self.output.flush()
            self.buffer += data
            require(len(self.buffer) <= 131072, "bounded qualification output")
            return bool(data)
        return True

    def line(self, timeout=8):
        end = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            require(time.monotonic() < end, self.name + " output timeout")
            require(self.pump(min(.1, max(0, end-time.monotonic()))), self.name + " unexpected stdout EOF")
            self.run.sample()
        raw, self.buffer = self.buffer.split(b"\n", 1)
        value = json.loads(raw)
        self.events.append(dict(elapsedSeconds=time.monotonic()-self.started, event=value))
        return value

    def send(self, op):
        self.process.stdin.write(canonical(dict(op=op)) + b"\n")
        self.process.stdin.flush()

    def command(self, op):
        self.send(op)
        return self.line()

    def close_input(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()

    def join(self, terminate=False, expected=None):
        if self.joined:
            return self.record["exitCode"]
        self.close_input()
        if terminate and self.process.poll() is None:
            self.process.terminate()
        try:
            code = self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.record["forcedKill"] = True
            self.process.kill()
            code = self.process.wait(timeout=3)
        while self.pump(0):
            if not select.select([self.process.stdout], [], [], 0)[0]:
                break
        self.process.stdout.close()
        self.output.close()
        self.errors.close()
        self.joined = True
        try:
            os.kill(self.process.pid, 0)
            absent = False
        except ProcessLookupError:
            absent = True
        self.record.update(exitCode=code, joined=True, observedAbsent=absent,
                           elapsedSeconds=time.monotonic()-self.started)
        save(self.directory / "process.json", self.record)
        require(absent, self.name + " PID still observed after numeric reap")
        if expected is not None:
            require(code == expected, f"{self.name} exit {code}, expected {expected}")
        return code


class Case:
    def __init__(self, run, name):
        self.run, self.name = run, name
        self.root = run.runtime / name
        self.root.mkdir(mode=0o700)
        self.root_inode = self.root.stat().st_ino
        self.endpoint = self.root / "s"
        self.socket_inode = None
        self.files = []
        self.children = []
        self.cleaned = False
        run.cases.append(self)

    def socket_ready(self):
        st = self.endpoint.lstat()
        require(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
                and st.st_uid == os.getuid(), "private socket")
        self.socket_inode = st.st_ino

    def launch(self, suffix, arguments):
        child = Child(self.run, self.name + "-" + suffix, self.endpoint, arguments)
        self.children.append(child)
        return child

    def file(self, suffix, value=None):
        path = self.run.runtime / (self.name + "-" + suffix)
        if value is not None:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(canonical(value))
        self.files.append(path)
        return path

    def remove_socket(self):
        require(all(c.joined for c in self.children if c.name.endswith("-service")
                    or c.name.endswith("-replacement") or c.name.endswith("-probe-server")),
                "service must join before endpoint removal")
        if self.endpoint.exists():
            st = self.endpoint.lstat()
            require(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid()
                    and (self.socket_inode is None or st.st_ino == self.socket_inode), "owned endpoint only")
            self.endpoint.unlink()
        self.socket_inode = None

    def cleanup(self):
        if self.cleaned:
            return
        require(all(c.joined for c in self.children), "join all case children before cleanup")
        self.remove_socket()
        for path in self.files:
            if path.exists():
                st = path.lstat()
                require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid(), "owned regular input only")
                path.unlink()
        require(self.root.lstat().st_ino == self.root_inode, "owned root identity")
        self.root.rmdir()  # Unexpected files are never recursively removed.
        self.cleaned = True
        self.run.cleanup.append(dict(root=str(self.root), endpoint=str(self.endpoint),
                                     absent=not self.root.exists(), filesAbsent=all(not p.exists() for p in self.files)))


class Run:
    def __init__(self, args):
        self.args = args
        self.executable = Path(args.executable).resolve(strict=True)
        self.scratch = Path(args.scratch).resolve(strict=True)
        self.output = Path(args.output).absolute()
        self.output.mkdir(mode=0o700)
        self.runtime = Path(tempfile.mkdtemp(prefix="r106.", dir=self.scratch))
        self.children, self.cases, self.cleanup, self.samples, self.results = [], [], [], [], []
        self.sentinel = self.output / "unrelated-sentinel"
        self.sentinel.write_bytes(os.urandom(32))
        self.sentinel_digest = digest(self.sentinel.read_bytes())
        self.started = time.monotonic()
        self.binary_digest = digest(self.executable.read_bytes())
        self.sample()

    def profile(self, endpoint):
        literal = json.dumps(str(endpoint))
        keychains = json.dumps(str(Path.home() / "Library/Keychains"))
        repo = Path(__file__).resolve().parents[1]
        return (f'(version 1)(allow default)(deny network*)'
                f'(allow network-bind (literal {literal}))'
                f'(allow network-inbound (literal {literal}))'
                f'(allow network-outbound (literal {literal}))'
                f'(deny file-read-data (subpath {keychains})'
                f' (literal {json.dumps(str(repo / ".env.local"))})'
                f' (subpath {json.dumps(str(repo / "tasks"))}))')

    def sample(self):
        def allocation(root):
            return sum(p.lstat().st_blocks*512 for p in root.rglob("*"))
        owned = allocation(self.scratch) + allocation(self.output)
        retained = allocation(self.output)
        free = shutil.disk_usage(self.scratch).free
        require(owned <= 4 << 30 and retained <= 128 << 20 and free >= 30 << 30, "resource ceiling")
        require(all(p.stat().st_size <= 32 << 20 for p in self.output.rglob("*.log")), "log ceiling")
        # Phase samples and new maxima suffice; no large repeated telemetry log.
        if not self.samples or owned > max(x["ownedBytes"] for x in self.samples) or free < min(x["freeBytes"] for x in self.samples):
            self.samples.append(dict(ownedBytes=owned, retainedBytes=retained, freeBytes=free))

    def feasibility(self):
        for behavior in ["echo", "partial", "trailing", "oversize", "stall", "drip", "interrupt", "write-stall", "connect-stall"]:
            case = Case(self, behavior)
            server = case.launch("probe-server", ["probe-server", "--endpoint", str(case.endpoint), "--behavior", behavior])
            server.close_input()
            require(server.line()["stage"] == "probe-ready", "probe readiness")
            case.socket_ready()
            client = case.launch("probe-client", ["probe-client", "--endpoint", str(case.endpoint), "--behavior", behavior])
            client.close_input()
            if behavior == "interrupt":
                for _ in range(20):
                    time.sleep(.2)
                    require(client.process.poll() is None, "interrupted client exited early")
                    os.kill(client.process.pid, signal.SIGUSR1)
            result = client.line()
            if behavior == "echo":
                require(result["bytes"] == 8192 and result["noSigpipe"] == 1, "Swift partial-delivery echo")
                require(server.line()["bytes"] == 8192, "Swift server framing")
            else:
                require(result.get("error") in ("frame", "timeout", "io"), "negative frame/transport refusal")
                require(result["elapsed"] < 6_000_000_000, "absolute bound")
                if behavior in ("stall", "drip", "interrupt", "write-stall"):
                    require(result["error"] == "timeout" and 4_900_000_000 <= result["elapsed"], "five-second absolute timeout")
                if behavior == "write-stall":
                    require(result["phase"] == "write", "actual blocked-write timeout")
                if behavior == "connect-stall":
                    require(result["phase"] == "connect", "queue-full connect refusal")
                if behavior == "interrupt":
                    require(result["signals"] >= 10, "actual interrupted waits")
            client.join(expected=0 if behavior == "echo" else 1)
            server.join(expected=1 if behavior == "drip" else 0)
            self.results.append(dict(case=behavior, result=result))
            case.cleanup()
        allowed, other = Case(self, "allowed"), Case(self, "other")
        child = allowed.launch("network", ["network-probe", "--endpoint", str(other.endpoint),
                                          "--keychains", str(Path.home()/"Library/Keychains")])
        child.close_input()
        result = child.line()
        require(all(result[k] for k in ("otherUnixDenied", "ipv4BindDenied", "ipv6BindDenied", "keychainReadDenied")), "sandbox negatives")
        child.join(expected=0)
        self.results.append(dict(case="sandbox", result=result))
        allowed.cleanup()
        other.cleanup()

    def service(self, case, suffix, host, client, delay_index=0, delay_ms=0):
        subject = str(uuid.uuid4())
        selection = case.file(suffix+"-selection.json", [dict(subject=subject, hostCap=host*10**9, clientCap=client*10**9)])
        descriptor = case.file(suffix+"-descriptor.json")
        arguments = ["service", "--endpoint", str(case.endpoint), "--selection", str(selection),
                     "--descriptor", str(descriptor)]
        if delay_index:
            arguments += ["--qualification-delay-index", str(delay_index), "--qualification-delay-ms", str(delay_ms)]
        child = case.launch(suffix, arguments)
        child.close_input()  # Service must survive launcher-control EOF.
        ready = child.line()
        require(ready["stage"] == "ready" and ready["pid"] == child.process.pid, "service readiness and PID")
        case.socket_ready()
        data = descriptor.read_bytes()
        require(len(data) <= 65536 and digest(data) == ready["descriptorSHA256"], "trusted descriptor selection")
        require(stat.S_IMODE(descriptor.stat().st_mode) == 0o600, "descriptor mode")
        (child.directory/"selected-descriptor.json").write_bytes(data)
        return dict(child=child, path=descriptor, digest=digest(data), descriptor=json.loads(data), subject=subject)

    def receiver(self, case, suffix, selected, override_digest=None):
        return case.launch(suffix, ["receiver", "--descriptor", str(selected["path"]),
                                   "--digest", override_digest or selected["digest"], "--subject", selected["subject"]])

    def eligible(self, child):
        report = child.command("exchange")
        require(report["stage"] == "eligible" and not report["lost"], "prompt eligible control")
        return report

    def campaign(self):
        prior = json.loads(Path(self.args.feasibility).read_text())
        require(prior["passed"] and prior["mode"] == "feasibility" and prior["executableSHA256"] == self.binary_digest,
                "successful actual-Swift feasibility for this executable required first")
        self.results.append(dict(feasibility=str(Path(self.args.feasibility).resolve()), sha256=digest(Path(self.args.feasibility).read_bytes())))
        case = Case(self, "primary")
        selected = self.service(case, "service", 180, 240, 4, 4250)
        originals, actions = [], []
        for suffix in ("receiver-a", "receiver-b"):
            child = self.receiver(case, suffix, selected)
            ready = child.line()
            originals.append(ready["originals"])
            actions.append(self.eligible(child))
            require(child.command("finish")["stage"] == "finished", "finish")
            child.join(expected=0)
            require(selected["child"].process.poll() is None, "same issuer survives receiver exit/control EOF")
        require(originals[0] == originals[1], "exact originals and full pin survive receiver replacement")
        requests = [json.loads(base64.b64decode(a["request"])) for a in actions]
        require(requests[0]["nonce"] != requests[1]["nonce"] and requests[0]["receiverIncarnation"] != requests[1]["receiverIncarnation"], "fresh independent receiver challenge")
        require(actions[0]["sent"] != actions[1]["sent"], "fresh original send bracket")
        require(actions[0]["evaluation"]["hostDeadline"] == actions[1]["evaluation"]["hostDeadline"]
                and actions[0]["evaluation"]["clientDeadline"] == actions[1]["evaluation"]["clientDeadline"], "immutable original deadlines")
        child = self.receiver(case, "receiver-loss", selected)
        child.line()
        self.eligible(child)
        child.command("finish")
        child.send("exchange")
        require(selected["child"].line()["stage"] == "reply-held", "kill during actual exchange")
        selected["child"].join(terminate=True, expected=-signal.SIGTERM)
        lost = child.line()
        require(lost["stage"] == "refused" and lost["lost"], "observed mid-exchange loss latches owner")
        require(child.command("evaluate-previous")["error"] == "invalidated", "old action invalid after observed loss")
        case.remove_socket()
        replacement = self.service(case, "replacement", 180, 240)
        require(replacement["descriptor"]["identity"] != selected["descriptor"]["identity"], "replacement full identity differs")
        require(child.command("exchange")["error"] == "invalidated", "available endpoint never revives failed owner")
        child.join(expected=0)
        old = self.receiver(case, "receiver-old-pin", selected)
        old.line()
        refusal = old.command("exchange")
        require(refusal["stage"] == "refused" and refusal["lost"], "new issuer cannot satisfy old originals")
        old.join(expected=0)
        wrong = self.receiver(case, "receiver-wrong-descriptor", replacement, selected["digest"])
        wrong.join(expected=1)
        fresh = self.receiver(case, "receiver-new-work", replacement)
        fresh.line()
        self.eligible(fresh)
        fresh.join(expected=0)
        replacement["child"].join(terminate=True, expected=-signal.SIGTERM)
        case.remove_socket()
        stalled = case.launch("probe-server", ["probe-server", "--endpoint", str(case.endpoint), "--behavior", "stall"])
        stalled.close_input()
        require(stalled.line()["stage"] == "probe-ready", "bounded fault-peer readiness")
        case.socket_ready()
        timed = self.receiver(case, "receiver-timeout", selected)
        timed.line()
        timeout = timed.command("exchange")
        require(timeout["error"] == "timeout" and timeout["lost"], "actual five-second timeout latches owner")
        require(timed.command("exchange")["error"] == "invalidated", "no retry after actual timeout")
        timed.join(expected=0)
        stalled.join(expected=0)
        self.results.append(dict(case="primary-continuity-loss-replacement", passed=True))
        case.cleanup()

        for lane, host, client in (("host-expiry", 4, 30), ("client-expiry", 30, 4), ("action-age", 180, 240)):
            case = Case(self, lane)
            selected = self.service(case, "service", host, client, 2 if lane=="host-expiry" else 0, 4250 if lane=="host-expiry" else 0)
            child = self.receiver(case, "receiver", selected)
            child.line()
            control = self.eligible(child)
            began = time.monotonic()
            if lane == "host-expiry":
                child.command("finish")
                child.send("exchange")
                held = selected["child"].line()
                require(held["stage"] == "reply-held", "authentic response retained before delay")
                result = child.line()
                require(result["stage"] == "expired" and result["evaluation"]["outcome"] == "hostExpired", "signed host-expiry outcome")
                require(result["response"] == held["response"] and result["signatureControl"]["nanoseconds"] < result["evaluation"]["hostDeadline"], "identical authentic pre-expiry reply")
                require(result["evaluation"]["r0"] == result["sent"] and result["evaluation"]["r1"]["nanoseconds"] - result["sent"]["nanoseconds"] < 5_000_000_000, "original bracket and sub-five-second receive")
            else:
                time.sleep(4.25 if lane=="client-expiry" else 10.5)
                result = child.command("evaluate")
                if lane == "client-expiry":
                    require(result["stage"] == "expired" and result["evaluation"]["outcome"] == "clientExpired", "client expiry after blocked prospective use")
                    require(result["request"] == control["request"] and result["response"] == control["response"], "same completed action")
                else:
                    require(result["stage"] == "refused" and result["error"] == "age", "action age after completed prompt exchange")
            elapsed = time.monotonic()-began
            self.results.append(dict(case=lane, elapsedSeconds=elapsed, control=control, negative=result))
            child.join(expected=0)
            selected["child"].join(terminate=True, expected=-signal.SIGTERM)
            case.cleanup()

    def finish(self, error=None):
        cleanup_errors = []
        for child in self.children:
            if not child.joined:
                try:
                    child.join(terminate=True)
                except Exception as exc:
                    cleanup_errors.append(str(exc))
        for case in self.cases:
            try:
                case.cleanup()
            except Exception as exc:
                cleanup_errors.append(str(exc))
        try:
            self.runtime.rmdir()
        except OSError as exc:
            cleanup_errors.append(str(exc))
        self.sample()
        sentinel_ok = self.sentinel.exists() and digest(self.sentinel.read_bytes()) == self.sentinel_digest
        result = dict(mode=self.args.mode, passed=error is None and not cleanup_errors and sentinel_ok,
                      error=error, cleanupErrors=cleanup_errors, executable=str(self.executable),
                      executableSHA256=self.binary_digest, results=self.results,
                      processes=[child.record for child in self.children], cleanup=self.cleanup,
                      runtimeRoot=str(self.runtime), runtimeAbsent=not self.runtime.exists(),
                      sentinelPreserved=sentinel_ok, sentinelSHA256=self.sentinel_digest,
                      resources=self.samples, elapsedSeconds=time.monotonic()-self.started)
        save(self.output/"result.json", result)
        print(json.dumps(dict(passed=result["passed"], result=str(self.output/"result.json"), error=error)))
        return result["passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--scratch", required=True, help="existing owned build/scratch root, included in resource accounting")
    parser.add_argument("--output", required=True, help="new retained evidence directory")
    parser.add_argument("--mode", required=True, choices=("feasibility", "campaign"))
    parser.add_argument("--feasibility", help="successful feasibility result.json for the identical executable")
    args = parser.parse_args()
    require(args.mode != "campaign" or args.feasibility, "campaign requires --feasibility")
    run = Run(args)
    error = None
    try:
        getattr(run, args.mode)()
    except Exception:
        error = traceback.format_exc()
    raise SystemExit(0 if run.finish(error) else 1)


if __name__ == "__main__":
    main()
