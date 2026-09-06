#!/usr/bin/env python3
"""Synthetic recovery model only. No Reach imports, model, network or encryption."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
MAX_RECORD = 1 << 20
MAX_EVENTS = 256
MAX_RECORDS = 8


class Refused(Exception):
    """An explicit model decision, never permission to rerun uncertain work."""


def private_root(path):
    root = Path(path)
    if not root.is_absolute() or root.resolve() != root or not root.is_relative_to('/private/tmp'):
        raise Refused('use a canonical private directory under /private/tmp')
    info = root.stat()
    if not root.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('root must be current-owner 0700')
    return root


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class Snapshot:
    """Atomic local process-reload image. SHA-256 detects damage, not attackers."""
    def __init__(self, root, name):
        self.root = private_root(root)
        self.path = self.root / name
        self.staged = self.root / (name + '.staged')

    def read(self):
        try:
            with self.path.open('rb') as stream:
                raw = stream.read(MAX_RECORD + 1)
        except FileNotFoundError:
            return None
        if len(raw) > MAX_RECORD:
            raise Refused('record too large')
        try:
            envelope = json.loads(raw)
            payload = envelope['payload']
            if envelope['sha256'] != hashlib.sha256(encoded(payload)).hexdigest():
                raise ValueError('checksum')
            return payload
        except (KeyError, TypeError, ValueError, RecursionError) as error:
            raise Refused('corrupt record') from error

    def write(self, payload, fault=None):
        raw = encoded({'payload': payload, 'sha256': hashlib.sha256(encoded(payload)).hexdigest()})
        if len(raw) > MAX_RECORD:
            raise Refused('record too large')
        fd = os.open(self.staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw[:len(raw) // 2] if fault == 'before-commit' else raw)
            stream.flush()
            os.fsync(stream.fileno())
        if fault == 'before-commit':
            os._exit(86)  # Owned synthetic child only: staged image is not authoritative.
        os.replace(self.staged, self.path)
        directory = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if fault == 'after-commit':
            os._exit(86)


def binding(generation=1, session=1, request=1, revision='fake-v1'):
    return dict(generation=generation, session=session, request=request, revision=revision)


class Controller:
    """One lifetime lock plus a persistent model owner counter; no timed takeover."""
    def __init__(self, root):
        self.root = private_root(root)
        self.snapshot = Snapshot(root, 'host.json')
        self.lock = os.open(self.root / 'owner.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.closed = False
        self.ready = set()
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            value = self.snapshot.read()
            if value is None:
                # An incomplete first image is not an empty, safe new authority.
                if self.snapshot.staged.exists():
                    raise Refused('incomplete initial record')
                value = dict(schema=1, owner=0, generations={})
            self.validate(value)
            value['owner'] += 1
            self.owner = value['owner']
            self.snapshot.write(value)
        except BlockingIOError as error:
            self.close()
            raise Refused('owner busy') from error
        except BaseException:
            self.close()
            raise

    @staticmethod
    def validate(value):
        try:
            assert value['schema'] == 1 and type(value['owner']) is int and value['owner'] >= 0
            assert isinstance(value['generations'], dict) and len(value['generations']) <= MAX_RECORDS
            for key, item in value['generations'].items():
                assert key == str(item['binding']['generation'])
                assert set(item['binding']) == {'generation', 'session', 'request', 'revision'}
                assert item['phase'] in {'active', 'queued', 'complete', 'cancelled', 'expired'}
                assert isinstance(item['events'], list) and len(item['events']) <= MAX_EVENTS
                assert [e['seq'] for e in item['events']] == list(range(len(item['events'])))
                assert type(item['expires']) is int
                assert type(item['received']) is int and -1 <= item['received'] < len(item['events'])
                if item['phase'] == 'active':
                    assert item['checkpoint']['next'] == len(item['events'])
        except (AssertionError, KeyError, TypeError) as error:
            raise Refused('incompatible or malformed model record') from error

    def close(self):
        if not self.closed:
            os.close(self.lock)
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def current(self, owner):
        if self.closed:
            raise Refused('owner closed')
        value = self.snapshot.read()
        self.validate(value)
        if owner != self.owner or value['owner'] != owner:
            raise Refused('stale owner')
        return value

    @staticmethod
    def match(value, expected, now):
        item = value['generations'].get(str(expected['generation']))
        if item is None:
            raise Refused('unknown generation; never automatically restart')
        if item['binding'] != expected:
            raise Refused('request or revision mismatch')
        if now >= item['expires'] or item['phase'] == 'expired':
            raise Refused('expired')
        return item

    def begin(self, expected, now=0):
        value = self.current(self.owner)
        if str(expected['generation']) in value['generations']:
            item = self.match(value, expected, now)
            return 'duplicate-' + item['phase']
        live = [g for g in value['generations'].values() if g['phase'] in ('active', 'queued')]
        if len(value['generations']) >= MAX_RECORDS:
            raise Refused('record capacity')
        active = any(g['phase'] == 'active' for g in live)
        queued = [g for g in live if g['phase'] == 'queued']
        if active and (len(queued) >= 3 or any(g['binding']['session'] == expected['session'] for g in queued)):
            raise Refused('waiting room full or session already waiting')
        phase = 'queued' if active else 'active'
        value['generations'][str(expected['generation'])] = dict(
            binding=copy.deepcopy(expected), phase=phase, expires=now + 900,
            checkpoint={'next': 0} if not active else None,
            events=[], received=-1, provider_starts=0 if active else 1)
        self.snapshot.write(value)
        if phase == 'active':
            self.ready.add(str(expected['generation']))
        return phase

    def recover(self, expected, now=0, provider_settled=True):
        value = self.current(self.owner)
        item = self.match(value, expected, now)
        if item['phase'] == 'active':
            # A remote uncertain execution holds its slot; a timeout is not proof of death.
            key = str(expected['generation'])
            if provider_settled:
                self.ready.add(key)
            else:
                self.ready.discard(key)
            return 'resume' if provider_settled else 'blocked-provider-owner-unknown'
        return {'queued': 'requeue', 'complete': 'replay-only', 'cancelled': 'cancelled'}[item['phase']]

    def promote(self, expected, now=0):
        value = self.current(self.owner)
        item = self.match(value, expected, now)
        if item['phase'] != 'queued' or any(g['phase'] == 'active' for g in value['generations'].values()):
            raise Refused('no active capacity')
        # Caller selects one eligible waiter; the probe makes no durable FIFO promise.
        item.update(phase='active', checkpoint={'next': 0}, provider_starts=1)
        self.snapshot.write(value)
        self.ready.add(str(expected['generation']))

    def advance(self, expected, owner, now=0, terminal=False, call=False, fault=None):
        value = self.current(owner)
        item = self.match(value, expected, now)
        if item['phase'] != 'active' or str(expected['generation']) not in self.ready:
            raise Refused('provider not active or ownership unsettled')
        if terminal and call:
            raise Refused('choose one event kind')
        if len(item['events']) >= MAX_EVENTS:
            raise Refused('publication capacity; do not emit')
        sequence = item['checkpoint']['next']
        kind = 'terminal' if terminal else ('call' if call else 'integer')
        event = dict(seq=sequence, kind=kind, value=sequence)
        if call:
            event['call_id'] = f"{expected['generation']}:{sequence}"
        item['events'].append(event)
        item['checkpoint'] = None if terminal else {'next': sequence + 1}
        if terminal:
            item['phase'] = 'complete'
        # The checkpoint and exact synthetic event become authoritative together.
        self.snapshot.write(value, fault=fault)
        return copy.deepcopy(event)  # Publication can occur only after commit.

    def replay(self, expected, after=-1, now=0):
        item = self.match(self.current(self.owner), expected, now)
        if not -1 <= after < len(item['events']):
            raise Refused('cursor outside committed history')
        return copy.deepcopy([event for event in item['events'] if event['seq'] > after])

    def receipt(self, expected, through, now=0):
        value = self.current(self.owner)
        item = self.match(value, expected, now)
        if not -1 <= through < len(item['events']):
            raise Refused('receipt beyond committed events')
        item['received'] = max(item['received'], through)
        self.snapshot.write(value)  # Receipt does not change client effects or checkpoints.

    def retire(self, expected, now=0, cancelled=False):
        value = self.current(self.owner)
        item = value['generations'].get(str(expected['generation']))
        if item is None or item['binding'] != expected:
            raise Refused('request or revision mismatch')
        if item['phase'] == 'active' and str(expected['generation']) not in self.ready:
            raise Refused('ownership unsettled; cannot release provider capacity')
        if not cancelled and now < item['expires']:
            raise Refused('not expired')
        item.update(phase='cancelled' if cancelled else 'expired', checkpoint=None, events=[], received=-1)
        self.snapshot.write(value)  # Minimal tombstone blocks automatic replacement work.


class Client:
    """Receipt/display dedup for a surviving client; no app-process crash guarantee."""
    def __init__(self):
        self.events = []

    def receive(self, event):
        seq = event['seq']
        if seq < len(self.events):
            if self.events[seq] != event:
                raise Refused('event replacement')
            return False
        if seq != len(self.events):
            raise Refused('event gap')
        self.events.append(copy.deepcopy(event))
        return True


class Effects:
    """Separate fake client journal and integer effect; intentionally no transaction across them."""
    def __init__(self, root):
        self.snapshot = Snapshot(root, 'effects.json')

    def read(self):
        return self.snapshot.read() or {'calls': {}, 'counter': 0}

    def invoke(self, call_id, fault=None):
        value = self.read()
        if call_id in value['calls']:
            known = value['calls'][call_id]
            if known['state'] == 'known':
                return known['result']
            raise Refused('tool outcome unknown; explicit safe resolution required')
        value['calls'][call_id] = {'state': 'unknown'}
        self.snapshot.write(value)  # Record intent before the local fake effect.
        value['counter'] += 1
        self.snapshot.write(value)
        if fault == 'after-effect':
            os._exit(86)
        value['calls'][call_id] = {'state': 'known', 'result': value['counter']}
        self.snapshot.write(value)
        return value['counter']


def worker(args):
    if args.action == 'effect':
        result = Effects(args.root).invoke('1:0', args.fault)
    else:
        with Controller(args.root) as host:
            if args.action == 'recover':
                result = host.recover(binding())
            else:
                host.recover(binding())
                result = host.advance(binding(), host.owner, terminal=args.terminal,
                                      fault=args.fault if args.fault != 'after-publish' else None)
                print(json.dumps(result), flush=True)
                if args.fault == 'after-publish':
                    os._exit(86)
                return
    print(json.dumps({'result': result}), flush=True)


def demo(root):
    if any(root.iterdir()):
        raise Refused('demo requires a fresh empty private directory')
    client = Client()
    with Controller(root) as host:
        host.begin(binding())
        client.receive(host.advance(binding(), host.owner))
        # Intentionally lose the receipt, then close/reload the model host.
    with Controller(root) as host:
        assert host.recover(binding()) == 'resume'
        for event in host.replay(binding()):
            client.receive(event)
        client.receive(host.advance(binding(), host.owner, terminal=True))
    with Controller(root) as host:
        assert host.recover(binding()) == 'replay-only'
        for event in host.replay(binding()):
            client.receive(event)
    assert [event['seq'] for event in client.events] == [0, 1]
    return dict(proof='synthetic-model-only', ordered_visible_sequences=[0, 1],
                terminal_replay='no new provider start', real_provider_proven=False,
                encryption_proven=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['demo', 'advance', 'recover', 'effect'])
    parser.add_argument('--root', required=True)
    parser.add_argument('--fault', choices=['before-commit', 'after-commit', 'after-publish', 'after-effect'])
    parser.add_argument('--terminal', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'demo':
            print(json.dumps(demo(private_root(args.root)), sort_keys=True))
        else:
            worker(args)
    except Refused as error:
        print(json.dumps({'refused': str(error)}))
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
