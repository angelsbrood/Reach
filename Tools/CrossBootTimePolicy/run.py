#!/usr/bin/env python3
"""Serial system-clock and actual cold-reboot qualification; no injected clocks."""
import argparse, io, json, os, re, shutil, stat, sys, tarfile, traceback
from pathlib import Path
sys.dont_write_bytecode = True
from rig import Rig, NETWORK_PROFILE, sha, write

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--scratch', type=Path, required=True)
parser.add_argument('--label', required=True)
parser.add_argument('--executable', type=Path, required=True)
parser.add_argument('--retain', type=Path, required=True)
parser.add_argument('--reuse-freshness', type=Path)
a = parser.parse_args()
base = a.scratch.resolve(strict=True)
assert str(base).startswith('/private/tmp/reach-s99.') and base.stat().st_uid == os.getuid()
assert stat.S_IMODE(base.stat().st_mode) == 0o700 and re.fullmatch('[a-z0-9-]+', a.label)
root = base / ('campaign-' + a.label); root.mkdir(mode=0o700)
retained = a.retain.resolve(strict=True) / root.name
assert not retained.exists()
executable = root / 'clock-qualification'; shutil.copyfile(a.executable, executable); executable.chmod(0o700)
vm = Rig(root, 'reach-s99-' + base.name.split('.', 1)[1] + '-' + a.label, base)
result = {'result': 'RUNNING', 'scope': 'conditional standalone clock policy; no generation recovery',
          'vm': vm.name, 'executableSHA256': sha(executable), 'injectedClocks': False}
product = Path(__file__).resolve().parent
write(vm.e / 'inputs.json', {'executableSHA256': sha(executable),
    'products': {str(p.relative_to(product)): sha(p) for p in product.rglob('*') if p.is_file()},
    'existingVMHelperSHA256': sha(product.parent / 'CrossBootRoleLifecycle/vm.py')})


def collect(label):
    _, data, _ = vm.user_exec(label, ['/usr/bin/tar', '-cf', '-', '--exclude=clock-qualification', '-C', vm.guest, '.'], timeout=30)
    assert len(data) <= 8 << 20
    destination = root / 'guest'; destination.mkdir(exist_ok=True, mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for entry in archive:
            path = Path(entry.name)
            assert not path.is_absolute() and '..' not in path.parts
            assert entry.isdir() or entry.isfile()
            target = destination / path
            if entry.isdir(): target.mkdir(exist_ok=True, parents=True, mode=0o700)
            else:
                assert entry.size <= 65536
                target.parent.mkdir(exist_ok=True, parents=True, mode=0o700)
                target.write_bytes(archive.extractfile(entry).read()); target.chmod(0o600)


def compare_observed_intervals(evaluations):
    intervals = []
    for first, second in zip(evaluations, evaluations[1:]):
        assert first['r0']['boot'] == second['r0']['boot'] and first['r0']['incarnation'] == second['r0']['incarnation']
        witness_delta = second['witness']['nanoseconds'] - first['witness']['nanoseconds']
        receiver_max = second['r1']['nanoseconds'] - first['r0']['nanoseconds']
        receiver_min = max(0, second['r0']['nanoseconds'] - first['r1']['nanoseconds'])
        assert witness_delta >= 0 and receiver_max >= 0
        # Witness samples occur inside each receiver request bracket. This is a finite observation.
        possible_violation = witness_delta > 2 * receiver_max + 1_000_000_000
        stricter_comparison = witness_delta <= 2 * receiver_min + 1_000_000_000
        intervals.append({'witnessDeltaNs': witness_delta, 'receiverElapsedLowerNs': receiver_min,
                          'receiverElapsedUpperNs': receiver_max, 'observedViolation': possible_violation,
                          'satisfiesEvenLowerBracketComparison': stricter_comparison})
        assert not possible_violation, 'observed rig profile violation'
    return intervals

try:
    vm.baseline('initial'); vm.idle('initial')
    if a.reuse_freshness:
        prior = a.reuse_freshness.resolve(strict=True)
        prior_result = json.loads((prior / 'RESULT.json').read_text())
        assert prior_result['executableSHA256'] == sha(executable)
        receipts = list((prior / 'evidence').glob('*-signed-system-delays.json'))
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_text())
        assert receipt['exitCode'] == 0 and receipt['joined'] and not receipt['timedOut']
        stdout = receipts[0].with_suffix('.stdout.log')
        assert sha(stdout) == receipt['stdoutSHA256']
        out = stdout.read_bytes()
        write(vm.e / 'freshness-reuse.json', {'source': str(prior), 'executableSHA256': sha(executable),
            'receiptSHA256': sha(receipts[0]), 'stdoutSHA256': sha(stdout), 'priorCampaignResult': prior_result['result']})
    else:
        _, out, _ = vm.run('signed-system-delays', ['/usr/bin/sandbox-exec', '-p', NETWORK_PROFILE, executable, 'freshness'], timeout=30)
    delays = json.loads(out)
    assert len(delays) == 2 and all(x['signatureOnlyWouldAllow'] and x['producedWhileConservativelyEligible'] for x in delays)
    assert [x['afterDelay']['outcome'] for x in delays] == ['hostExpired', 'clientExpired']
    write(vm.e / 'signed-system-delays.json', delays)
    print('EARNED signed delay and post-blocking refusals', flush=True)
    vm.clone(); vm.start('boot-1')
    vm.rpc('prepare-owned-guest', f"""set -eu
[[ $EUID == 0 ]]
[[ ! -e {vm.guest} && ! -L {vm.guest} ]]
/bin/mkdir -m 700 {vm.guest}
/usr/sbin/chown 503:20 {vm.guest}
""")
    # Only the fixed executable enters this content-free fixture. The pin travels over owned pipes.
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode='w') as archive:
        info = archive.gettarinfo(str(executable), arcname='clock-qualification')
        info.uid = 503; info.gid = 20; info.mode = 0o700
        with executable.open('rb') as source: archive.addfile(info, source)
    vm.user_exec('transfer-owned-executable', ['/usr/bin/tar', '-xf', '-', '-C', vm.guest], body=bundle.getvalue(), timeout=30)
    _, out, _ = vm.user_exec('guest-executable-binding', ['/usr/bin/shasum', '-a', '256', vm.guest + '/clock-qualification'])
    assert out.decode().split()[0] == sha(executable)
    vm.start_witness(executable, 'witness-original')
    original_identity = vm.hello['identity']; original_pid = vm.witness.pid
    vm.receiver('seed'); collect('collect-seed')
    original_manifest_hash = sha(root / 'guest/originals.json')
    seed = vm.events['seed']
    vm.stop('first-stop')
    assert vm.witness is not None and vm.witness.pid == original_pid and vm.witness.poll() is None
    surviving_sample = vm.witness_exchange({'kind': 'sample'})
    write(vm.e / 'witness-during-cold-stop.json', {'pid': original_pid, 'identity': original_identity, 'sampleReply': surviving_sample})
    vm.start('boot-2')
    assert vm.witness is not None and vm.witness.pid == original_pid and vm.witness.poll() is None
    vm.receiver('postboot'); collect('collect-postboot')
    assert sha(root / 'guest/originals.json') == original_manifest_hash
    positive = vm.events['postboot-positive']; complete = vm.events['postboot-complete']
    assert seed['receiver']['boot'] != positive['receiver']['boot'] == complete['receiver']['boot']
    assert seed['receiver']['incarnation'] != positive['receiver']['incarnation']
    assert seed['witnessIdentity'] == positive['witnessIdentity'] == complete['witnessIdentity'] == original_identity
    assert seed['originals'] == positive['originals'] == complete['originals']
    assert all(x['outcome'] == 'eligible' for x in positive['evaluations'])
    assert vm.events['host-expired']['outcome'] == 'hostExpired' and vm.events['client-expired']['outcome'] == 'clientExpired'
    evaluations = positive['evaluations'] + [vm.events['host-expired'], vm.events['client-expired'], vm.events['unobserved-loss-bounded-use']]
    intervals = compare_observed_intervals(evaluations)
    write(vm.e / 'observed-rate-intervals.json', {'assumptionIsNotProven': True, 'intervals': intervals})
    assert vm.witness is None  # The original process was actually stopped/joined in the loss test.
    vm.start_witness(executable, 'witness-replacement')
    assert vm.hello['identity'] != original_identity
    vm.receiver('replacement'); collect('collect-replacement')
    assert sha(root / 'guest/originals.json') == original_manifest_hash
    vm.stop_witness('replacement-witness-stop')
    guest_receipts = [json.loads((root / ('guest/' + phase + '-process.json')).read_text()) for phase in ['seed', 'postboot', 'replacement']]
    assert all(x['joined'] and x['exitCode'] == 0 for x in guest_receipts)
    vm.rpc('remove-owned-guest-material', f"""set -eu
[[ $EUID == 503 ]]
[[ -d {vm.guest} && ! -L {vm.guest} ]]
[[ $(/usr/bin/stat -f %u {vm.guest}) == 503 ]]
/bin/rm -rf {vm.guest}
[[ ! -e {vm.guest} && ! -L {vm.guest} ]]
print OWNED_GUEST_MATERIAL_ABSENT
""", user=True)
    vm.stop('final-stop'); vm.dispose()
    result.update(result='PASS', actualColdReboot=True, receiverBoots=[seed['receiver']['boot'], positive['receiver']['boot']],
        originalWitness=original_identity, originalWitnessPID=original_pid,
        originalManifestSHA256=original_manifest_hash, originalBytesUnchanged=True,
        positiveConservativeEligibility=True, independentHostAndClientExpiry=True,
        actualSignedDelayRefusals=True, replacementRefused=True, actualWitnessProcessLossExercised=True,
        observedRateViolation=False, finiteIntervalObservations=len(intervals),
        guestFixtureAbsent=True, ownedCloneAbsent=True, guestProcessReceipts=guest_receipts)
except BaseException as error:
    result.update(result='FAIL', failure=str(error), traceback=traceback.format_exc())
    if vm.boot is not None:
        try: collect('collect-failure')
        except BaseException as collection: result['collectionFailure'] = str(collection)
finally:
    if vm.witness is not None:
        try: vm.stop_witness('failure-witness-stop')
        except BaseException as stop:
            result['witnessStopFailure'] = str(stop)
            p = vm.witness; p.terminate()
            try: p.wait(timeout=10)
            except Exception: p.kill(); p.wait(timeout=10)
            vm.witnessLog.close()
            vm.children.append({'label': 'failure-witness-termination', 'pid': p.pid, 'exitCode': p.returncode, 'joined': True})
            vm.witness = None
    if vm.boot is not None:
        try: vm.stop('failure-stop')
        except BaseException as stop: result['stopFailure'] = str(stop)
    if vm.boot is None and vm.target.exists():
        try: vm.dispose()
        except BaseException as disposal: result['disposalFailure'] = str(disposal)
    vm.sample(); vm.save()
    result.update(knownHostChildren=len(vm.children), allKnownHostChildrenJoined=all(x['joined'] for x in vm.children),
                  clonePresent=vm.target.exists(), ownedBootLive=vm.boot is not None, witnessLive=vm.witness is not None,
                  resourceObservation='Sampled whole-volume free-space delta is not exclusive COW allocation. No exhaustive boot packet or opaque-descendant history is claimed.')
    if result['clonePresent'] or result['ownedBootLive'] or result['witnessLive']: result['result'] = 'FAIL'
    write(root / 'RESULT.json', result)
    retained.mkdir(mode=0o700)
    shutil.copytree(vm.e, retained / 'evidence')
    if (root / 'guest').exists(): shutil.copytree(root / 'guest', retained / 'guest')
    shutil.copyfile(root / 'RESULT.json', retained / 'RESULT.json')
    total = sum(p.stat().st_size for p in a.retain.rglob('*') if p.is_file())
    assert total <= 256 << 20, 'retained evidence ceiling'
    executable.unlink()
    print(json.dumps(result, sort_keys=True), flush=True)
sys.exit(0 if result['result'] == 'PASS' else 1)
