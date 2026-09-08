#!/usr/bin/env python3
"""Qualify an already-built normal reachd executable with owned local artifacts."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import time
import sys

sys.dont_write_bytecode = True


def directory(path):
    path = Path(path)
    info = path.lstat()
    assert path.is_absolute() and path.resolve() == path
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
    assert stat.S_IMODE(info.st_mode) == 0o700
    return path


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Child:
    def __init__(self, campaign, label, args, *, external=False):
        self.campaign = campaign
        self.label = label
        self.out = (campaign.path / 'logs' / (label + '.stdout')).open('xb')
        self.err = (campaign.path / 'logs' / (label + '.stderr')).open('xb')
        command = args if external else [str(campaign.executable), *args]
        command = ['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)(deny network*)', *command]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.err, start_new_session=True)
        self.buffer = b''
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.record = dict(label=label, pid=self.process.pid, command=command, joined=False)
        campaign.evidence['processes'].append(self.record)
        campaign.save()

    def until(self, predicate, timeout=180):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.campaign.sample()
            for _key, _event in self.selector.select(0.1):
                data = os.read(self.process.stdout.fileno(), 65536)
                self.out.write(data)
                self.out.flush()
                self.buffer += data
                assert len(self.buffer) <= 16 << 20
                while b'\n' in self.buffer:
                    line, self.buffer = self.buffer.split(b'\n', 1)
                    try:
                        value = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if predicate(value):
                        return value
            if self.process.poll() is not None:
                return None
        raise TimeoutError(self.label)

    def join(self, timeout=180):
        if self.record['joined']:
            return self.record['exit_code']
        self.until(lambda _: False, timeout)
        code = self.process.wait(timeout=2)
        self.record.update(exit_code=code, joined=True)
        self.out.close()
        self.err.close()
        self.process.stdout.close()
        self.selector.close()
        self.campaign.save()
        return code

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()  # Only this exact launched child.
        return self.join()


class Campaign:
    def __init__(self, args):
        self.args = args
        self.scratch = directory(args.scratch)
        assert str(self.scratch).startswith('/private/tmp/reach-s93.')
        self.model = directory(args.model)
        self.requests = directory(args.requests)
        assert Path(args.campaign).name == args.campaign
        self.path = self.scratch / args.campaign
        self.path.mkdir(mode=0o700)
        for name in ('bin', 'reports', 'logs', 'roots'):
            (self.path / name).mkdir(mode=0o700)
        self.executable = self.path / 'bin/reachd'
        assert Path(args.binary).is_file() and Path(args.binary).stat().st_size <= 192 << 20
        assert Path(args.metallib).is_file() and Path(args.metallib).stat().st_size <= 64 << 20
        shutil.copyfile(args.binary, self.executable)
        self.executable.chmod(0o700)
        shutil.copyfile(args.metallib, self.path / 'bin/mlx.metallib')
        self.evidence = dict(executable=str(self.executable), sha256=digest(self.executable), bytes=self.executable.stat().st_size,
            metallibSHA256=digest(args.metallib), profileSHA256=digest(self.model / 'profile.json'),
            supervisorSHA256=digest(__file__), helperSHA256={name:digest(Path(__file__).with_name(name)) for name in ('native.py','boundary.py')}, processes=[], cells=[], resources=[])
        self.last_sample = 0
        self.sample()
        self.save()

    def sample(self, force=False):
        if not force and time.monotonic() - self.last_sample < 10:
            return
        allocated = 0
        for path in self.scratch.rglob('*'):
            try:
                allocated += path.lstat().st_blocks * 512
            except FileNotFoundError:
                pass
        free = shutil.disk_usage(self.scratch).free
        fixtures = 0
        for path in (self.path / 'roots').rglob('*'):
            try:
                fixtures += path.lstat().st_blocks * 512
            except FileNotFoundError:
                pass
        retained = sum(path.stat().st_size for path in (self.path / 'reports').glob('*'))
        assert allocated <= 32 << 30 and free >= 20 << 30 and fixtures <= 3 << 30 and retained <= 1 << 30
        assert all(path.stat().st_size <= 192 << 20 for path in (self.path / 'logs').glob('*'))
        self.evidence['resources'].append(dict(allocated=allocated, free=free, fixtureAllocated=fixtures, reportBytes=retained))
        self.last_sample = time.monotonic()

    def save(self):
        (self.path / 'evidence.json').write_text(json.dumps(self.evidence, sort_keys=True, indent=2) + '\n')

    def child(self, label, args):
        return Child(self, label, args)

    def command(self, label, args, expected=0, *, external=False):
        child = Child(self, label, args, external=external)
        try:
            code = child.join()
        finally:
            if not child.record['joined']:
                child.kill()
        assert code == expected, (label, code)
        return child

    @contextlib.contextmanager
    def root(self, label):
        root = self.path / 'roots' / label
        guardian = self.child(label + '-init', ['durable-local', 'init', '--root', str(root), '--model', str(self.model)])
        ready = guardian.until(lambda value: value.get('stage') == 'ready')
        if not ready:
            guardian.join()
            raise RuntimeError('Initialization refused: ' + label)
        try:
            yield root
        finally:
            guardian.process.send_signal(signal.SIGTERM)
            retired = guardian.until(lambda value: value.get('stage') in ('retired', 'cleanup-blocked'))
            if not retired or retired['stage'] != 'retired':
                # Keep the foreground creator alive with its exact cleanup
                # capability. Never replace it with a credential search.
                self.evidence['cleanupGuardianPID'] = guardian.process.pid
                self.save()
                raise RuntimeError('Cleanup guardian retains authority: ' + str(guardian.process.pid))
            assert guardian.join() == 0 and not root.exists()

    def report(self, label):
        return self.path / 'reports' / (label + '.json')

    def refusal(self, label, root):
        self.command(label, ['durable-local', 'recover', '--root', str(root)], expected=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('scratch', 'campaign', 'binary', 'metallib', 'model', 'requests'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--mode', choices=('crash', 'reference', 'boundary'), required=True)
    parser.add_argument('--routes', nargs='+', choices=('ordinary', 'guided', 'required', 'allowed', 'combined'), default=['ordinary', 'guided', 'required', 'allowed', 'combined'])
    parser.add_argument('--reference-dir', help='Successful crash report directory, required by reference mode.')
    args = parser.parse_args()
    if args.mode == 'reference':
        assert args.reference_dir
        directory(args.reference_dir)
    campaign = Campaign(args)
    try:
        if args.mode == 'boundary':
            from boundary import run
        else:
            from native import run
        run(campaign)
        campaign.sample(force=True)
        assert all(item['joined'] for item in campaign.evidence['processes'])
        assert not list((campaign.path / 'roots').iterdir())
        campaign.evidence['result'] = 'PASS'
    except BaseException as error:
        campaign.evidence['result'] = 'FAIL'
        campaign.evidence['failure'] = repr(error)
        raise
    finally:
        campaign.save()


if __name__ == '__main__':
    main()
