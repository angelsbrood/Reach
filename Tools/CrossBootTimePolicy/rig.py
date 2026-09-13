"""Owned S99 campaign mechanics; existing S98 VM recipe is imported read-only."""
from pathlib import Path
import base64, hashlib, json, os, re, select, subprocess, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'CrossBootRoleLifecycle'))
from vm import VM, TART, STORE, GOLD, sha, write

MANIFEST = Path('/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/shared/current-baseline.json')
NETWORK_PROFILE = '(version 1)(allow default)(deny network*)'

class Rig(VM):
    def __init__(self, root, name, scratch):
        self.scratch = scratch
        self.witness = None
        self.buffers = {}
        self.events = {}
        self.witnesses = []
        super().__init__(root, name)

    def sample(self):
        super().sample()
        owned = sum(p.stat().st_blocks * 512 for p in self.scratch.rglob('*') if p.is_file() and not p.is_symlink())
        evidence = sum(p.stat().st_size for p in self.e.rglob('*') if p.is_file())
        logs = [p.stat().st_size for p in self.e.rglob('*.log')]
        self.samples[-1].update(ownedScratchAllocatedBytes=owned, evidenceBytes=evidence)
        assert owned <= 8 << 30 and evidence <= 256 << 20 and max(logs or [0]) <= 64 << 20, 'S99 resource ceiling'

    def baseline(self, label):
        super().baseline(label)
        assert sha(MANIFEST) == '0c358893d344a2597db2c844743e983ce37251b912d7be78252471e60df7ca7c'
        write(self.e / ('shared-manifest-' + label + '.json'), {'path': str(MANIFEST), 'sha256': sha(MANIFEST)})

    def frame(self, process, label, timeout=30):
        deadline = time.monotonic() + timeout
        buf = self.buffers.pop(process.pid, b'')
        while b'\n' not in buf:
            remaining = deadline - time.monotonic()
            assert remaining > 0, label + ' bounded pipe timeout'
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            assert ready, label + ' bounded pipe timeout'
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                assert not buf, label + ' incomplete frame'
                return None
            buf += part
            assert len(buf.split(b'\n', 1)[0]) <= 65536, 'bounded pipe frame'
        raw, rest = buf.split(b'\n', 1)
        self.buffers[process.pid] = rest
        value = json.loads(raw)
        assert json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == raw, 'canonical frame'
        with (self.e / 'protocol.log').open('ab') as log:
            line = json.dumps({'hostObservationNs': time.monotonic_ns(), 'source': label, 'frame': value}, sort_keys=True).encode() + b'\n'
            assert log.tell() + len(line) <= 64 << 20
            log.write(line)
        return value

    def send(self, process, value):
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        assert len(raw) <= 65536
        process.stdin.write(raw + b'\n'); process.stdin.flush()

    def start_witness(self, executable, label):
        assert self.witness is None
        self.witnessLabel = label
        self.witnessLog = (self.e / (label + '.stderr.log')).open('xb')
        command = ['/usr/bin/sandbox-exec', '-p', NETWORK_PROFILE, str(executable), 'witness']
        self.witnessStart = time.monotonic()
        self.witness = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.witnessLog, env=self.env)
        self.commands.append({'label': label, 'command': command})
        self.hello = self.frame(self.witness, label + '-hello')
        assert self.hello and self.hello['profile']['domain'] == 'reach-clock-qualification-v1'
        entry = {'label': label, 'pid': self.witness.pid, 'hello': self.hello, 'executableSHA256': sha(executable)}
        self.witnesses.append(entry); write(self.e / (label + '-started.json'), entry)

    def witness_exchange(self, request):
        assert self.witness is not None and self.witness.poll() is None, 'observed witness loss'
        self.send(self.witness, request)
        reply = self.frame(self.witness, self.witnessLabel)
        assert reply is not None, 'observed witness EOF'
        return reply

    def stop_witness(self, label):
        if self.witness is None: return
        p = self.witness
        reply = self.witness_exchange({'kind': 'quit'})
        assert reply == {'kind': 'bye'}
        code = p.wait(timeout=10)
        self.witnessLog.close(); p.stdin.close(); p.stdout.close()
        record = {'label': label, 'pid': p.pid, 'exitCode': code, 'joined': True,
                  'seconds': time.monotonic() - self.witnessStart, 'witness': self.hello['identity']}
        self.children.append(record); write(self.e / (label + '-joined.json'), record)
        self.witness = None
        assert code == 0
        self.save()

    def receiver(self, phase):
        # This known Python child reports the guest executable's actual pid/exit/wait result.
        script = r"""
import json,os,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]);phase=sys.argv[2]
command=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)',str(root/'clock-qualification'),'receiver',phase,str(root)]
start=time.monotonic();p=subprocess.Popen(command)
receipt={'pid':p.pid,'wrapperPID':os.getpid(),'command':command,'joined':False}
path=root/(phase+'-process.json');path.write_text(json.dumps(receipt,sort_keys=True)+'\n')
code=p.wait();receipt.update(exitCode=code,joined=True,elapsedSeconds=time.monotonic()-start)
path.write_text(json.dumps(receipt,sort_keys=True)+'\n');sys.exit(code)
"""
        command = [str(TART), 'exec', '-i', self.name, '/bin/launchctl', 'asuser', '503',
                   '/usr/bin/sudo', '-H', '-u', 'threshold-auto', '/usr/bin/python3', '-c', script, self.guest, phase]
        self.commands.append({'label': 'receiver-' + phase, 'command': command})
        error_log = (self.e / ('receiver-' + phase + '.stderr.log')).open('xb')
        start = time.monotonic()
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log, env=self.env)
        failure = None
        try:
            self.send(p, self.hello)
            while True:
                assert time.monotonic() - start <= 360, 'receiver phase ceiling'
                request = self.frame(p, 'receiver-' + phase)
                if request is None: break
                kind = request['kind']
                if kind == 'event':
                    name = request['event']; assert re.fullmatch('[a-z0-9-]+', name)
                    data = base64.b64decode(request['evidence'], validate=True)
                    assert len(data) <= 65536
                    value = json.loads(data)
                    assert name not in self.events
                    self.events[name] = value
                    (self.e / (name + '.json')).write_bytes(data)
                    print('EARNED ' + name, flush=True)
                    reply = {'kind': 'ack'}
                elif kind == 'controller-stop-witness':
                    assert phase == 'postboot' and self.witnessLabel == 'witness-original'
                    self.stop_witness('original-witness-unobserved-loss')
                    reply = {'kind': 'ack'}
                else:
                    assert kind in ['fixtures', 'certificate', 'sample']
                    reply = self.witness_exchange(request)
                self.send(p, reply)
            code = p.wait(timeout=15)
            assert code == 0, 'guest receiver ' + phase + ' exited ' + str(code)
        except BaseException as error:
            failure = str(error)
            p.terminate()
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=10)
            raise
        finally:
            error_log.close(); p.stdin.close(); p.stdout.close()
            receipt = {'label': 'receiver-' + phase, 'pid': p.pid, 'exitCode': p.returncode,
                       'joined': True, 'failure': failure, 'seconds': time.monotonic() - start}
            self.children.append(receipt); write(self.e / ('receiver-' + phase + '-joined.json'), receipt)
            self.sample(); self.save()
