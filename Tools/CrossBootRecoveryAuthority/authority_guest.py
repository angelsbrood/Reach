#!/usr/bin/env python3
"""S100 serial actual-record qualification in one owned guest; secrets stay there."""
import base64, hashlib, json, os, select, shutil, stat, subprocess, sys, time, traceback, uuid
from pathlib import Path
sys.dont_write_bytecode = True
BASE = Path(sys.argv[1]).resolve(strict=True)
PHASE = sys.argv[2]
assert str(BASE).startswith('/Users/threshold-auto/reach-s100-') and os.getuid() == 503
assert BASE.stat().st_uid == 503 and stat.S_IMODE(BASE.stat().st_mode) == 0o700
os.umask(0o077)
for name in ['logs', 'reports', 'roots', 'control', 'secrets', 'originals', 'tmp']:
    (BASE / name).mkdir(exist_ok=True, mode=0o700)
EXE = BASE / 'bin/reachd'
PROFILE = '(version 1)(allow default)(deny network*)'
MODEL_DENIED = len(sys.argv) > 3 and sys.argv[3] == 'model-denied'
record = dict(phase=PHASE, wrapperPID=os.getpid(), processes=[], result='RUNNING')

def raw(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
def write(path, value): path.write_bytes(raw(value) + b'\n'); path.chmod(0o600)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(): write(BASE / 'reports' / (PHASE + '.json'), record)
def controller(value):
    allocated = sum(p.lstat().st_blocks * 512 for p in BASE.rglob('*'))
    fixture_bytes = sum(p.lstat().st_blocks * 512 for p in (BASE / 'fixtures').rglob('*'))
    free = shutil.disk_usage(BASE).free
    assert allocated <= 32 << 30 and fixture_bytes <= 3 << 30 and free >= 30 << 30
    value = dict(value, resources=dict(guestAllocatedBytes=allocated, guestFixtureAllocatedBytes=fixture_bytes, guestFreeBytes=free))
    data = raw(value); assert len(data) <= 65536
    sys.stdout.buffer.write(data + b'\n'); sys.stdout.buffer.flush()
    line = sys.stdin.buffer.readline(65538); assert line.endswith(b'\n') and len(line) <= 65537
    return json.loads(line)
def event(name, evidence):
    assert controller(dict(kind='event', name=name, evidence=evidence)) == {'kind': 'ack'}
def signed(encoded): return json.loads(base64.b64decode(json.loads(base64.b64decode(encoded))['body']))
def capture(args):
    start = time.monotonic(); p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try: out, err = p.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate(timeout=10); raise
    finally:
        record['processes'].append(dict(label='guest-observation', pid=p.pid, command=args,
            exitCode=p.returncode, joined=True, seconds=time.monotonic()-start))
        save()
    assert p.returncode == 0; return out

def boot():
    value = capture(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid']).decode().strip().lower()
    assert str(uuid.UUID(value)) == value; return value

def command(label, args, secret=None, initial=None, expected=0, no_model=False, lose_witness=False):
    # One outer sandbox is selected before this controller starts. macOS
    # rejects applying a different nested sandbox after the first one.
    if no_model and str(args[0]) == 'authenticate': assert MODEL_DENIED
    args = [str(x) for x in args]
    fd = os.open(secret, os.O_RDONLY | os.O_NOFOLLOW) if secret else None
    if fd is not None: args += ['--unlock-secret-fd', str(fd)]
    cmd = [str(EXE), 'durable-recovery-authority', *args]
    start = time.monotonic(); item = dict(label=label, command=cmd, joined=False, frames=[], certificates=[], inheritedNetworkDenial=True, inheritedModelReadDenial=MODEL_DENIED)
    err = (BASE / 'logs' / (label + '.stderr.log')).open('xb')
    out = (BASE / 'logs' / (label + '.stdout.log')).open('xb')
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                         pass_fds=() if fd is None else (fd,))
    if fd is not None: os.close(fd)
    item['pid'] = p.pid; record['processes'].append(item); save()
    buf = b''
    try:
        if initial is not None: p.stdin.write(initial + b'\n'); p.stdin.flush()
        while True:
            assert time.monotonic() - start < 90, label + ' command timeout'
            if b'\n' not in buf:
                ready, _, _ = select.select([p.stdout], [], [], 1)
                if not ready: continue
                part = os.read(p.stdout.fileno(), 4096)
                if not part: assert not buf; break
                out.write(part); out.flush(); buf += part
                assert out.tell() <= 192 << 20 and len(buf.split(b'\n', 1)[0]) <= 65536
                if b'\n' not in buf: continue
            line, buf = buf.split(b'\n', 1)
            value = json.loads(line); assert raw(value) == line
            stage = value.get('stage')
            if stage in ['challenge', 'observe-witness']:
                if stage == 'observe-witness' and lose_witness:
                    assert controller(dict(kind='stop-witness')) == {'kind': 'ack'}
                    reply = dict(stage='witness-observation', lost=True)
                else: reply = controller(dict(kind='witness', request=value))
                if reply.get('certificate'):
                    item['certificates'].append(signed(reply['certificate']))
                p.stdin.write(raw(reply) + b'\n'); p.stdin.flush()
            else: item['frames'].append(value)
        code = p.wait(timeout=10)
        item.update(exitCode=code, joined=True, seconds=time.monotonic()-start)
        if expected is not None: assert code == expected, label + ' exit ' + str(code)
        if code != 0: assert not item['frames'], label + ' published after refusal'
        return item
    finally:
        if p.poll() is None:
            p.terminate()
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=10)
        item.update(exitCode=p.returncode, joined=True, seconds=time.monotonic()-start)
        p.stdin.close(); p.stdout.close(); out.close(); err.close(); save()

def pair_path(name): return BASE / 'control' / (name + '.json')
def pair_save(pair): write(pair_path(pair['name']), pair)
def pair_load(name): return json.loads(pair_path(name).read_bytes())
def role_args(pair, role):
    return ['--owner-receipt', pair[role]['receipt'], '--expected-receipt-digest', pair[role]['digest']]
def pair_args(pair):
    return ['--host-receipt', pair['host']['receipt'], '--host-digest', pair['host']['digest'],
            '--client-receipt', pair['client']['receipt'], '--client-digest', pair['client']['digest']]
def hashes(pair):
    result = {}
    for role in ['host', 'client']:
        root = Path(pair[role]['root'])
        for p in sorted(root.rglob('*')):
            if p.is_file() and 'keys' not in p.relative_to(root).parts:
                assert not p.is_symlink(); result[str(p.relative_to(BASE))] = sha(p)
        for p in sorted((BASE / 'control').glob(pair['name'] + '-' + role + '.json*')):
            if p.is_file(): result[str(p.relative_to(BASE))] = sha(p)
    return result

def metadata():
    return {flag: capture(['/usr/bin/security', flag, '-d', 'user']).decode()
            for flag in ['list-keychains', 'default-keychain']}

def fixture():
    p = BASE / 'fixtures/public-model.json'; value = json.loads(p.read_bytes()); old = sha(p)
    observed = capture(['/usr/bin/osascript', '-l', 'JavaScript', '-e',
        'ObjC.import("Foundation"); $.NSProcessInfo.processInfo.operatingSystemVersionString.js']).decode().strip()
    value['descriptor']['backend'] = 'arm64-little-endian;cpu;' + observed
    p.write_bytes(raw(value)); p.chmod(0o600)
    write(BASE / 'reports/fixture.json', dict(hostPublicModelSHA256=old, guestPublicModelSHA256=sha(p),
        backend=value['descriptor']['backend'], beforeOriginalProvisioning=True))
    write(BASE / 'reports/keychains-before.json', metadata())

# The installed compiler selection was executed and proven by native-05. This
# owned launcher only supports original preparation; authentication denies fixtures.
compiler = '/Library/Developer/CommandLineTools/usr/bin/clang++'
sdk = '/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk'
launcher = BASE / 'compiler-launcher'; launcher.mkdir(mode=0o700, exist_ok=True)
shim = launcher / 'g++'
shim.write_text('#!/usr/bin/python3\nimport os,sys\nos.execv(' + repr(compiler) + ', [' + repr(compiler) + ']+' +
                repr(['-no-canonical-prefixes', '-isysroot', sdk, '-isystem', sdk + '/usr/include/c++/v1']) + '+sys.argv[1:])\n')
shim.chmod(0o700)
os.environ['PATH'] = str(launcher) + ':' + str(Path(compiler).parent) + ':' + os.environ.get('PATH', '/usr/bin:/bin')
os.environ['TMPDIR'] = str(BASE / 'tmp')
assert 'MLX_DISABLE_COMPILE' not in os.environ

def original(name, caps):
    assert not list((BASE / 'roots').iterdir()), 'two-role Keychain ceiling'
    if name == 'a': fixture()
    pair = dict(name=name, boot=boot(), registrationSubject=str(uuid.uuid4()))
    response = controller(dict(kind='witness', request=dict(stage='register', subject=pair['registrationSubject'],
                                                           hostSeconds=caps[0], clientSeconds=caps[1])))
    assert response['stage'] == 'originals'
    originals = base64.b64decode(response['originals'], validate=True)
    decoded = json.loads(originals)
    pair['originals'] = decoded
    pair['registrations'] = {role: signed(decoded[role]) for role in ['host', 'client']}
    pair['configuration'] = str(BASE / 'control' / (name + '-configuration.json'))
    pair['export'] = str(BASE / 'control' / (name + '-admission.json'))
    pair_save(pair)
    command(name + '-provision', ['provision', '--public-model', BASE / 'fixtures/public-model.json',
        '--request', BASE / 'fixtures/requests/ordinary.json', '--output', pair['configuration']], initial=originals)
    for role in ['host', 'client']:
        secret = BASE / 'secrets' / (name + '-' + role)
        secret.write_text(os.urandom(32).hex()); secret.chmod(0o600)
        pair[role] = dict(root=str(BASE / 'roots' / (name + '-' + role)),
                          receipt=str(BASE / 'control' / (name + '-' + role + '.json')), secret=str(secret))
        pair_save(pair)
        item = command(name + '-init-' + role, ['init', '--root', pair[role]['root'], '--role', role,
            '--configuration', pair['configuration'], '--owner-receipt', pair[role]['receipt']], secret=secret)
        assert len(item['frames']) == 1 and item['frames'][0]['stage'] == 'ready'
        pair[role]['digest'] = item['frames'][0]['ownerReceiptDigest']; pair_save(pair)
    args = [*pair_args(pair), '--export', pair['export']]
    admitted = command(name + '-admit', ['admit', *args, '--model', BASE / 'fixtures/model',
        '--request', BASE / 'fixtures/requests/ordinary.json'], secret=pair['host']['secret'])['frames'][0]
    assert admitted['stage'] == 'original-admission'
    pair['issuer'] = admitted['issuer']; pair['exportDigest'] = admitted['exportDigest']; pair_save(pair)
    accepted = command(name + '-accept', ['accept', *args, '--original-issuer', pair['issuer'],
        '--successful-export-digest', pair['exportDigest']], secret=pair['client']['secret'])['frames'][0]
    assert accepted['admission'] == admitted['diagnostic']['admission']
    pair['diagnostic'] = admitted['diagnostic']; pair['hashes'] = hashes(pair); pair_save(pair)
    for path in pair['hashes']:
        target = BASE / 'originals' / name / path
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True); shutil.copyfile(BASE / path, target); target.chmod(0o600)
    event(name + '-original-real-records', dict(boot=pair['boot'], hashes=pair['hashes'], admission=pair['diagnostic'],
        independentRegistrations=pair['registrations'], successfulOriginalAcceptance=True))

def authenticate(pair, role, label, expected=0, extra=(), wrong=False, loss=False):
    secret = pair[role]['secret']
    if wrong:
        secret = BASE / 'secrets/wrong'; secret.write_text(os.urandom(32).hex()); secret.chmod(0o600)
    return command(label, ['authenticate', *role_args(pair, role), *extra], secret=secret,
                   expected=expected, no_model=True, lose_witness=loss)

def postboot(name):
    pair = pair_load(name); observed = boot(); assert observed != pair['boot']
    assert hashes(pair) == pair['hashes']
    if name == 'a': authenticate(pair, 'host', 'a-original-key-refusal', expected=1, wrong=True)
    results = {}
    for role in ['host', 'client']:
        item = authenticate(pair, role, name + '-postboot-' + role)
        d = item['frames'][0]; results[role] = d
        assert d['admission'] == pair['diagnostic']['admission'] and d['ticket'] == pair['diagnostic']['ticket']
        assert d['evaluation']['r']['boot'] == observed
        assert d['evaluation']['r0']['incarnation'] != pair['diagnostic']['evaluation']['r0']['incarnation']
    assert hashes(pair) == pair['hashes']
    event(name + '-postboot-original-authority', dict(originalBoot=pair['boot'], currentBoot=observed,
        originalRecordsUnchanged=True, noModelFilesReadable=True, host=results['host'], client=results['client']))
    if name == 'a':
        for role in ['host', 'client']:
            item = authenticate(pair, role, 'a-blocked-' + role, expected=1, extra=['--block-milliseconds', '11000'])
            assert item['seconds'] >= 11 and len(item['certificates']) == 1 and not item['frames']
        assert hashes(pair) == pair['hashes']
        event('actual-blocking-consumes-original-age', dict(roles=['host', 'client'], delayMilliseconds=11000,
            noDiagnosticPublication=True, originalRecordsUnchanged=True))
    if name in ['a', 'b']:
        short = 'host' if name == 'a' else 'client'; other = 'client' if name == 'a' else 'host'
        limit = pair['registrations'][short]['deadline']; long = pair['registrations'][other]['deadline']; index = 0
        while True:
            index += 1; assert index <= 30
            item = authenticate(pair, short, name + '-expiry-observation-' + str(index), expected=None)
            assert len(item['certificates']) == 1
            sample = item['certificates'][0]['sample']['nanoseconds']
            assert sample < long
            if sample >= limit:
                assert item['exitCode'] == 1 and not item['frames']; break
            remaining = (limit - sample) / 1e9
            event(name + '-original-deadline-wait-' + str(index), dict(expiringRole=short, secondsRemaining=remaining))
            time.sleep(min(20, remaining + 0.1))
        for role in ['host', 'client']:
            item = authenticate(pair, role, name + '-expired-refusal-' + role, expected=1)
            w = item['certificates'][0]['sample']['nanoseconds']; assert limit <= w < long
        assert hashes(pair) == pair['hashes']
        event(name + '-' + short + '-expiry-independent', dict(expiredRole=short, expiredDeadline=limit,
            otherDeadline=long, witnessSample=sample, noPublication=True, originalRecordsUnchanged=True))
    else:
        item = authenticate(pair, 'host', 'c-observed-witness-loss', expected=1, extra=['--observe-witness'], loss=True)
        assert len(item['certificates']) == 1 and not item['frames']
        replacement = controller(dict(kind='replacement-witness'))
        assert replacement['identity'] != pair['originals']['pin']
        item = authenticate(pair, 'client', 'c-replacement-cannot-adopt', expected=1)
        assert not item['frames'] and hashes(pair) == pair['hashes']
        event('observed-loss-and-replacement-refuse', dict(noPublication=True, originalRecordsUnchanged=True,
            originalWitness=pair['originals']['pin'], replacementWitness=replacement['identity']))
    retire(pair)

def retire(pair):
    observed = boot()
    for role in ['host', 'client']:
        if role not in pair: continue
        root = Path(pair[role]['root'])
        if not root.exists(): continue
        assert pair[role].get('digest'), 'unpublished original creator requires correction'
        after = observed != pair['boot']
        item = command(PHASE + '-retire-' + role, ['retire', *role_args(pair, role), *(['--after-boot'] if after else [])],
            secret=pair[role]['secret'] if after else None, no_model=True)
        assert item['frames'][0]['stage'] == 'retired' and not root.exists()
    assert not list((BASE / 'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
    pair['retired'] = True; pair_save(pair)
    event(pair['name'] + '-original-ownership-retired-' + PHASE, dict(rootAbsence=True, keychainAbsence=True,
        afterBoot=observed != pair['boot'], witnessCertificateNotRequested=True))

try:
    if PHASE.startswith('original-'):
        name = PHASE.rsplit('-', 1)[1]
        original(name, {'a': (150, 480), 'b': (480, 90), 'c': (180, 240)}[name])
    elif PHASE.startswith('postboot-'): postboot(PHASE.rsplit('-', 1)[1])
    elif PHASE.startswith('cleanup'):
        for p in sorted((BASE / 'control').glob('[abc].json')):
            pair = json.loads(p.read_bytes())
            if not pair.get('retired'): retire(pair)
        assert not list((BASE / 'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
        before = json.loads((BASE / 'reports/keychains-before.json').read_bytes())
        after = metadata(); assert before == after
        write(BASE / 'reports/keychains-after.json', after)
        shutil.rmtree(BASE / 'secrets'); record['secretsAbsent'] = True
    else: raise ValueError('unselected phase')
    record['result'] = 'PASS'
except BaseException as error:
    record.update(result='FAIL', failure=str(error), traceback=traceback.format_exc())
finally:
    record['rootObservations'] = [str(p.relative_to(BASE)) for p in (BASE / 'roots').iterdir()]
    record['keychainPaths'] = [str(p.relative_to(BASE)) for p in BASE.rglob('*.keychain-db')]
    record['knownWorkersJoined'] = all(p['joined'] for p in record['processes'])
    save()
    controller(dict(kind='phase-result', evidence={k:v for k,v in record.items() if k != 'processes'}))
sys.exit(0 if record['result'] == 'PASS' else 1)
