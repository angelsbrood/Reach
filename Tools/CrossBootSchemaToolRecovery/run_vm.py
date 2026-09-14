#!/usr/bin/env python3
"""Owned S105 authority campaign: one cold-booted VM and one serial host witness."""
import argparse, hashlib, io, json, os, re, select, shutil, stat, subprocess, sys, tarfile, time, traceback
from pathlib import Path
sys.dont_write_bytecode = True
PRODUCT = Path(__file__).resolve().parent
sys.path.insert(0, str(PRODUCT.parent / 'CrossBootRoleLifecycle'))
from vm import VM, TART, sha, write
BINDINGS = {
'/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/shared/current-baseline.json': 'e2e97d565f2d644753fd7680e07f18368110816dde9ba69ab324b13f0331dea9',
'/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/os-maintenance-0913/qualification.json': '22ac4e0686fe3da837162e2b74a5bc52a59cf3616534d96cb3acc2f18ce9eb75',
'/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/rpc-maintenance-0907/threshold-tart-guest-agent': 'e520451185ec1ec64727d317ac6733ab33b80acec8b361f49250269f8ac4f7ab'}
parser = argparse.ArgumentParser(description=__doc__)
for name in ['scratch', 'fixtures', 'executable', 'fixture-executable', 'metallib', 'retain']: parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--label', required=True)
parser.add_argument('--campaign', choices=['full','faults'], default='full')
a = parser.parse_args(); base = a.scratch.resolve(strict=True); fixtures = a.fixtures.resolve(strict=True)
assert str(base).startswith('/private/tmp/reach-s105.') and base.stat().st_uid == os.getuid() and stat.S_IMODE(base.stat().st_mode) == 0o700
assert str(fixtures).startswith('/private/tmp/reach-s93.s105.') and fixtures.name == 'fixtures'
assert re.fullmatch('[a-z0-9-]+', a.label)
root = base / ('schema-tool-' + a.label); root.mkdir(mode=0o700)

def raw(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

class NativeVM(VM):
    def __init__(self, *args):
        self.witness = None; self.buffers = {}; self.events = {}; self.phaseResults = {}; self.witnesses = []; self.guestAllocated = 0; self.guestFixtures = 0; self.initialOwned = None
        super().__init__(*args)
    def baseline(self, label):
        super().baseline(label)
        assert all(sha(p) == h for p, h in BINDINGS.items()), 'current S105 rig binding'
        write(self.e / ('s105-rig-' + label + '.json'), BINDINGS)
    def sample(self):
        super().sample(); allocated = 0
        for folder in [base, fixtures.parent]:
            for p in folder.rglob('*'):
                try: allocated += p.lstat().st_blocks * 512
                except FileNotFoundError: pass
        fixture_bytes = sum(p.lstat().st_blocks * 512 for p in fixtures.parent.rglob('*'))
        retained = sum(p.lstat().st_blocks * 512 for p in a.retain.rglob('*'))
        allocated += retained
        if self.initialOwned is None: self.initialOwned=allocated
        charge=self.initialOwned + self.samples[-1]['volumeFreeDropBytes']
        assert charge <= 20 << 30
        self.samples[-1]['conservativeAddedVolumeCharge']=charge
        self.samples[-1].update(aggregateOwnedAllocatedBytes=allocated+self.guestAllocated, fixtureAllocatedBytes=fixture_bytes+self.guestFixtures)
        assert allocated+self.guestAllocated <= 32 << 30 and fixture_bytes+self.guestFixtures <= 3 << 30
    def frame(self, p, label, timeout=45):
        end = time.monotonic() + timeout; buf = self.buffers.pop(p.pid, b'')
        while b'\n' not in buf:
            remaining = end - time.monotonic(); assert remaining > 0, label + ' frame timeout'
            ready, _, _ = select.select([p.stdout], [], [], remaining); assert ready, label + ' frame timeout'
            part = os.read(p.stdout.fileno(), 4096)
            if not part: assert not buf, label + ' incomplete frame'; return None
            buf += part; assert len(buf.split(b'\n', 1)[0]) <= 65536
        line, rest = buf.split(b'\n', 1); self.buffers[p.pid] = rest
        value = json.loads(line); assert raw(value) == line
        with (self.e / 'protocol.log').open('ab') as log:
            log.write(raw(dict(hostObservationNs=time.monotonic_ns(), source=label, frame=value)) + b'\n')
            assert log.tell() <= 192 << 20
        return value
    def send(self, p, value):
        data = raw(value); assert len(data) <= 65536
        p.stdin.write(data + b'\n'); p.stdin.flush()
    def start_witness(self, label):
        assert self.witness is None
        self.witnessLabel = label; self.witnessLog = (self.e / (label + '.stderr.log')).open('xb')
        profile = '(version 1)(allow default)(deny network*)(deny file-read-data (subpath "/Users/nellymoon/Library/Keychains") (literal "/Users/nellymoon/Documents/Swift/Reach/.env.local") (subpath "/Users/nellymoon/Documents/Swift/Reach/tasks"))'
        command = ['/usr/bin/sandbox-exec', '-p', profile, str(a.executable), 'durable-recovery-authority', 'witness']
        self.witnessCertificates=0; self.witnessRegistrations=0
        self.witnessStart = time.monotonic()
        self.witness = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.witnessLog, env=self.env)
        self.commands.append(dict(label=label, command=command))
        self.hello = self.frame(self.witness, label)
        assert self.hello['stage'] == 'witness-ready'
        entry = dict(label=label, pid=self.witness.pid, hello=self.hello, executableSHA256=sha(a.executable))
        self.witnesses.append(entry); write(self.e / (label + '-started.json'), entry)
        return self.hello
    def join_witness(self, label, expected):
        p = self.witness; code = p.wait(timeout=10)
        self.witnessLog.close(); p.stdin.close(); p.stdout.close()
        receipt = dict(label=label, pid=p.pid, exitCode=code, joined=True, seconds=time.monotonic()-self.witnessStart, identity=self.hello['identity'], certificates=self.witnessCertificates, registrations=self.witnessRegistrations)
        self.children.append(receipt); write(self.e / (label + '-joined.json'), receipt); self.witness = None; self.save()
        assert code == expected
    def exchange(self, request):
        assert self.witness is not None and self.witness.poll() is None
        self.send(self.witness, request); reply = self.frame(self.witness, self.witnessLabel)
        if reply is None:
            assert self.witnessLabel == 'witness-replacement' and request['stage'] == 'challenge'
            self.join_witness('replacement-refused-original-registrations', 1)
            return dict(stage='certificate')
        if reply.get('certificate'):
            self.witnessCertificates += 1; assert self.witnessCertificates<=128
        if request.get('stage')=='register':
            assert reply.get('originals'); self.witnessRegistrations += 2; assert self.witnessRegistrations<=16
        return reply
    def stop_witness(self, label):
        if self.witness is None: return
        if self.witness.poll() is None:
            reply = self.exchange(dict(stage='quit')); assert reply == dict(stage='witness-bye')
        self.join_witness(label, 0)
    def phase(self, phase):
        action=phase.split('-',1)[1] if phase.startswith(('normal-','fixture-')) else phase
        denied = action in ['resume-probe','resume-guided','ready-primary','terminal-primary','duplicate-primary','retire-primary'] or action.startswith('cleanup')
        profile = '(version 1)(allow default)(deny network*)'
        if denied: profile += '(deny file-read-data (subpath "' + self.guest + '/original-inputs") (subpath "' + self.guest + '/fixtures/requests"))'
        if action in ['terminal-primary','duplicate-primary'] or action.startswith('cleanup'): profile += '(deny file-read-data (subpath "' + self.guest + '/fixtures/model") (subpath "' + self.guest + '/fixtures/state-model"))'
        command = [str(TART), 'exec', '-i', self.name, '/bin/launchctl', 'asuser', '503', '/usr/bin/sudo', '-H', '-u', 'threshold-auto',
                   '/usr/bin/sandbox-exec', '-p', profile, '/usr/bin/python3', self.guest + '/guest.py', self.guest, phase,
                   'original-inputs-denied' if denied else 'ordinary']
        err = (self.e / (phase + '.stderr.log')).open('xb'); start = time.monotonic()
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, env=self.env)
        self.commands.append(dict(label=phase, command=command)); failure = None
        try:
            while True:
                assert time.monotonic() - start < 540
                value = self.frame(p, phase)
                if value is None: break
                self.guestAllocated = value['resources']['guestAllocatedBytes']
                self.guestFixtures = value['resources']['guestFixtureAllocatedBytes']
                self.sample()
                kind = value['kind']
                if kind == 'witness': reply = self.exchange(value['request'])
                elif kind == 'event':
                    name = value['name']; assert re.fullmatch('[a-z0-9-]+', name) and name not in self.events
                    self.events[name] = value['evidence']; write(self.e / (name + '.json'), value['evidence'])
                    print('EARNED ' + name, flush=True); reply = dict(kind='ack')
                elif kind == 'phase-result': self.phaseResults[phase] = value['evidence']; reply = dict(kind='ack')
                elif kind == 'stop-witness': self.stop_witness('original-witness-observed-loss'); reply = dict(kind='ack')
                elif kind == 'replacement-witness': reply = self.start_witness('witness-replacement')
                else: raise ValueError('unselected controller request')
                self.send(p, reply)
            code = p.wait(timeout=15)
            assert code == 0 and self.phaseResults[phase]['result'] == 'PASS', phase + ' failed; inspect guest report'
        except BaseException as error:
            failure = str(error)
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=10)
                except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=10)
            raise
        finally:
            err.close(); p.stdin.close(); p.stdout.close()
            receipt = dict(label=phase, pid=p.pid, exitCode=p.returncode, joined=True, failure=failure, seconds=time.monotonic()-start)
            self.children.append(receipt); write(self.e / (phase + '-joined.json'), receipt); self.sample(); self.save()

vm = NativeVM(root, 'reach-s105-' + base.name.split('.', 1)[1] + '-schema-tool-' + a.label)
vm.guest = '/Users/threshold-auto/' + vm.name
result = dict(result='RUNNING', scope='normal Llama schema fallback and separately prescribed tool precedence native cold-reboot qualification' if a.campaign == 'full' else 'schema next-pass native delay only; no reboot gate selected', vm=vm.name, guest=vm.guest)
write(root / 'inputs.json', dict(campaign=a.campaign, executable=str(a.executable), executableSHA256=sha(a.executable), fixtureExecutableSHA256=sha(a.fixture_executable), metallibSHA256=sha(a.metallib),
    sources={p.name: sha(p) for p in PRODUCT.glob('*.py')}, existingVMRecipeSHA256=sha(PRODUCT.parent / 'CrossBootRoleLifecycle/vm.py'),
    fixtureSHA256={str(p.relative_to(fixtures)): sha(p) for p in sorted((fixtures/'model').iterdir())+sorted((fixtures/'state-model').iterdir())+[fixtures/'requests/native-schema-tool.json']}))
payload = False; clean = False
fixtureFiles=sorted((fixtures/'model').iterdir())+sorted((fixtures/'state-model').iterdir())+[fixtures/'requests/native-schema-tool.json']
assert all(p.is_file() and not p.is_symlink() for p in fixtureFiles)

def collect(label):
    # Enumerated public evidence roots keep original encrypted record copies;
    # basename exclusions would also omit originals/.../roots on BSD tar.
    _, data, _ = vm.user_exec(label, ['/usr/bin/tar', '-cf', '-', '-C', vm.guest,
        'guest.py', 'budget.py', 'control', 'logs', 'reports', 'originals'], timeout=30)
    assert len(data) < 192 << 20
    destination = root / 'guest'; destination.mkdir(mode=0o700, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            p = Path(member.name); assert not p.is_absolute() and '..' not in p.parts and (member.isdir() or member.isfile())
            target = destination / p
            if member.isdir(): target.mkdir(exist_ok=True, parents=True, mode=0o700)
            else:
                assert member.size <= 192 << 20
                target.parent.mkdir(exist_ok=True, parents=True, mode=0o700)
                target.write_bytes(archive.extractfile(member).read()); target.chmod(0o600)
try:
    vm.clone(); vm.start('authority-initial-boot')
    vm.rpc('prepare-owned-authority-guest', 'set -eu\n[[ $EUID == 0 ]]\n[[ ! -e ' + vm.guest + ' && ! -L ' + vm.guest + ' ]]\n/bin/mkdir -m 700 ' + vm.guest + '\n/usr/sbin/chown 503:20 ' + vm.guest + '\n')
    bundle = root / 'payload.tar'
    with tarfile.open(bundle, 'w') as archive:
        files = [(a.executable, 'bin/reachd', 0o700), (a.fixture_executable, 'bin/reach-allowed-recovery-fixture', 0o700), (a.metallib, 'bin/mlx.metallib', 0o600), (PRODUCT / 'guest.py', 'guest.py', 0o600), (PRODUCT / 'budget.py', 'budget.py', 0o600)]
        files += [(p, 'fixtures/' + str(p.relative_to(fixtures)), 0o600) for p in fixtureFiles]
        for source, name, mode in files:
            info = archive.gettarinfo(str(source), arcname=name); info.uid = 503; info.gid = 20; info.mode = mode
            with source.open('rb') as data: archive.addfile(info, data)
    vm.user_exec('transfer-owned-authority-payload', ['/usr/bin/tar', '-xf', '-', '-C', vm.guest], body=bundle.read_bytes(), timeout=60)
    payload = True
    vm.rpc('private-authority-parents', 'set -eu\n[[ $EUID == 503 ]]\n/bin/chmod 700 ' + vm.guest + '/bin ' + vm.guest + '/fixtures ' + vm.guest + '/fixtures/model ' + vm.guest + '/fixtures/requests ' + vm.guest + '/fixtures/state-model\n', user=True)
    vm.phase('feasibility')
    prepared=vm.events['exact-common-preparation-frozen']
    assert prepared['normal']['executableSHA256']==sha(a.executable) and prepared['fixture']['executableSHA256']==sha(a.fixture_executable)
    assert prepared['common']['metallibSHA256']==sha(a.metallib)
    assert prepared['normal']['modelSHA256']=={p.name:sha(p) for p in (fixtures/'model').iterdir()}
    assert prepared['fixture']['modelSHA256']=={p.name:sha(p) for p in (fixtures/'state-model').iterdir()}
    witnesses={}
    if a.campaign == 'full':
        for lane in ['normal','fixture']:
            vm.start_witness(lane+'-primary-witness');original_witness=vm.witness.pid;original_identity=vm.hello['identity']
            vm.phase(lane+'-original-primary');collect('collect-'+lane+'-probe')
            vm.stop(lane+'-probe-cold-stop');vm.start(lane+'-probe-cold-boot')
            assert vm.witness.pid==original_witness and vm.hello['identity']==original_identity
            vm.phase(lane+'-resume-probe')
            collect('collect-'+lane+'-guided');vm.stop(lane+'-guided-cold-stop');vm.start(lane+'-guided-cold-boot')
            assert vm.witness.pid==original_witness and vm.hello['identity']==original_identity
            vm.phase(lane+'-resume-guided')
            for phase in ['ready-primary','terminal-primary','duplicate-primary','retire-primary']:vm.phase(lane+'-'+phase)
            budget=prepared[lane]['protocolBudget']
            assert vm.witnessCertificates==budget['certificates']['primary'] and vm.witnessRegistrations==2
            witnesses[lane+'Primary']=dict(pid=original_witness,identity=original_identity,certificates=vm.witnessCertificates)
            vm.stop_witness(lane+'-primary-witness-complete')
            vm.start_witness(lane+'-reference-witness')
            assert vm.hello['identity']!=original_identity
            vm.phase(lane+'-reference')
            assert vm.witnessCertificates==budget['certificates']['reference'] and vm.witnessRegistrations==2
            witnesses[lane+'Reference']=dict(pid=vm.witness.pid,identity=vm.hello['identity'],certificates=vm.witnessCertificates)
            vm.stop_witness(lane+'-reference-witness-complete')
            collect('collect-'+lane+'-complete')
        result.update(actualColdReboots=4, normalSchemaContinuation='PASS',prescribedToolPrecedence='PASS',
            freshReadyZeroForwardDelivery='PASS',zeroOneRegistrationDuplicateReplay='PASS',pendingForcedSuffix='PASS',
            exactIndependentReferences='PASS',zeroModelTerminalReplay='PASS')
    vm.start_witness('normal-schema-fault-witness');vm.phase('normal-faults')
    assert vm.witnessCertificates==prepared['normal']['protocolBudget']['certificates']['faults'] and vm.witnessRegistrations==2
    vm.stop_witness('normal-schema-fault-witness-complete')
    result.update(result='PASS',campaign=a.campaign,schemaNextPassBlockingAge='PASS',witnesses=witnesses,
        originalAdmissionOncePerIndependentPair=True,serialPairs=5 if a.campaign=='full' else 1,maximumLiveRoleKeychains=2)

except BaseException as error:
    result.update(result='FAIL', failure=str(error), traceback=traceback.format_exc())
finally:
    if vm.boot is not None and payload:
        cleanup_attempt = 0
        while not clean:
            cleanup_attempt += 1; phase = 'cleanup-' + str(cleanup_attempt)
            try:
                vm.phase(phase); cleanup = vm.phaseResults[phase]
                clean = cleanup['knownWorkersJoined'] and not cleanup['rootObservations'] and not cleanup['keychainPaths'] and cleanup['secretsAbsent']
                assert clean
            except BaseException as error:
                result.setdefault('cleanupFailures', []).append(str(error))
                result.update(result='FAIL', cleanupOwnerRetained=True)
                write(root / 'cleanup-owner-retained.json', result)
                try: collect('collect-failed-cleanup-' + str(cleanup_attempt))
                except BaseException as collection: result['collectionFailure'] = str(collection)
                print('CLEANUP OWNER RETAINED; bounded correction can signal ' + str(root / 'retry-cleanup'), flush=True)
                # Preserve this live Popen owner so the original guest boot can
                # still be numerically joined after an in-scope cleanup repair.
                retry = root / 'retry-cleanup'
                while not retry.exists(): vm.sample(); time.sleep(5)
                info = retry.lstat()
                assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
                assert retry.read_bytes() == b'retry\n'; retry.unlink()
        result['cleanupOwnerRetained'] = False
        try: collect('collect-final-authority-evidence')
        except BaseException as error: result['collectionFailure'] = str(error)
    elif not payload: clean = True
    try: vm.stop_witness('witness-final-stop')
    except BaseException as error: result['witnessStopFailure'] = str(error)
    if clean:
        if vm.boot is not None:
            try:
                if payload:
                    vm.rpc('remove-owned-authority-payload', 'set -eu\n[[ $EUID == 503 ]]\n[[ -d ' + vm.guest + ' && ! -L ' + vm.guest + ' ]]\n[[ $(/usr/bin/stat -f %u ' + vm.guest + ') == 503 ]]\n/bin/rm -rf ' + vm.guest + '\n[[ ! -e ' + vm.guest + ' && ! -L ' + vm.guest + ' ]]\nprint OWNED_AUTHORITY_PAYLOAD_ABSENT\n', user=True)
                vm.stop('authority-final-stop')
            except BaseException as error: result['stopFailure'] = str(error)
        if vm.boot is None and vm.target.exists():
            try: vm.dispose()
            except BaseException as error: result['disposalFailure'] = str(error)
    vm.sample(); vm.save()
    result.update(productRetirement=clean, clonePresent=vm.target.exists(), ownedBootLive=vm.boot is not None,
        knownHostChildrenJoined=all(x['joined'] for x in vm.children), hostChildren=len(vm.children), phases=vm.phaseResults,
        resourceObservation='Sampled aggregate owned allocation and whole-volume free delta; no exclusive COW or exhaustive opaque descendant claim.')
    if result['result'] == 'PASS' and (not clean or vm.target.exists() or vm.witness is not None or any(k.endswith('Failure') for k in result)):
        result['result'] = 'FAIL'
    write(root / 'RESULT.json', result)
    retained = a.retain.resolve(strict=True) / root.name; retained.mkdir(mode=0o700)
    for name in ['evidence', 'guest']:
        if (root / name).exists(): shutil.copytree(root / name, retained / name)
    for name in ['RESULT.json', 'inputs.json']: shutil.copyfile(root / name, retained / name)
    assert sum(p.stat().st_size for p in a.retain.rglob('*') if p.is_file()) <= 1 << 30
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['result'] == 'PASS' else 1)
