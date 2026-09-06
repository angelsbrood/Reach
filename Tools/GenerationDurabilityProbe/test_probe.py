"""Deterministic synthetic cases; subprocess exits kill only owned probe children."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
from probe import Client, Controller, Effects, MAX_RECORD, Refused, Snapshot, binding, private_root


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        base = private_root(os.environ['REACH_DURABILITY_SCRATCH'])
        self.root = Path(tempfile.mkdtemp(prefix='case-', dir=base))
        self.addCleanup(shutil.rmtree, self.root)

    def child(self, action, fault=None, terminal=False):
        args = [sys.executable, '-B', str(Path(__file__).with_name('probe.py')),
                action, '--root', str(self.root)]
        if fault:
            args += ['--fault', fault]
        if terminal:
            args += ['--terminal']
        # subprocess.run kills and joins its one owned child on timeout.
        result = subprocess.run(args, capture_output=True, text=True, timeout=5,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result.stderr, '')
        return result

    def test_checkpoint_publication_crash_boundaries(self):
        for prior_events in (0, 1):
            for fault in ('before-commit', 'after-commit', 'after-publish'):
                with self.subTest(prior_events=prior_events, fault=fault):
                    # Isolate each deterministic case, using at most one child.
                    for item in self.root.iterdir():
                        item.unlink()
                    client = Client()
                    with Controller(self.root) as host:
                        host.begin(binding())
                        if prior_events:
                            client.receive(host.advance(binding(), host.owner))
                    result = self.child('advance', fault)
                    self.assertEqual(result.returncode, 86)
                    if fault == 'after-publish':
                        client.receive(json.loads(result.stdout))
                    else:
                        self.assertEqual(result.stdout, '')
                    with Controller(self.root) as host:
                        self.assertEqual(host.recover(binding()), 'resume')
                        committed = prior_events + (fault != 'before-commit')
                        image = host.current(host.owner)['generations']['1']
                        self.assertEqual(image['checkpoint']['next'], committed)
                        for event in host.replay(binding()):
                            client.receive(event)
                        client.receive(host.advance(binding(), host.owner))
                        self.assertEqual([e['seq'] for e in client.events], list(range(committed + 1)))
                        self.assertEqual([e['value'] for e in client.events], list(range(committed + 1)))

    def test_receipt_loss_duplicate_replay_and_terminal(self):
        client = Client()
        with Controller(self.root) as host:
            host.begin(binding())
            client.receive(host.advance(binding(), host.owner))
            # No receipt reaches the host.
        result = self.child('advance', 'after-commit', terminal=True)
        self.assertEqual(result.returncode, 86)
        with Controller(self.root) as host:
            self.assertEqual(host.recover(binding()), 'replay-only')
            for _ in range(2):
                for event in host.replay(binding()):
                    client.receive(event)
            self.assertEqual([e['kind'] for e in client.events], ['integer', 'terminal'])
            host.receipt(binding(), 1)
            self.assertEqual(host.replay(binding(), after=1), [])
            self.assertEqual(host.begin(binding()), 'duplicate-complete')
            self.assertEqual(host.current(host.owner)['generations']['1']['provider_starts'], 1)
            with self.assertRaisesRegex(Refused, 'not active'):
                host.advance(binding(), host.owner)

    def test_owner_lock_and_old_fence(self):
        with Controller(self.root) as first:
            first.begin(binding())
            owner = first.owner
            result = self.child('recover')
            self.assertEqual(result.returncode, 2)
            self.assertIn('owner busy', result.stdout)
        with Controller(self.root) as second:
            self.assertGreater(second.owner, owner)
            second.recover(binding())
            with self.assertRaisesRegex(Refused, 'stale owner'):
                second.advance(binding(), owner)
            self.assertEqual(second.advance(binding(), second.owner)['seq'], 0)

    def test_admission_queue_and_uncertain_external_owner(self):
        with Controller(self.root) as host:
            self.assertEqual(host.begin(binding()), 'active')
            self.assertEqual(host.begin(binding()), 'duplicate-active')
            for number in (2, 3, 4):
                self.assertEqual(host.begin(binding(number, number, number)), 'queued')
            with self.assertRaisesRegex(Refused, 'waiting room'):
                host.begin(binding(5, 5, 5))
        with Controller(self.root) as host:
            self.assertEqual(host.recover(binding(), provider_settled=False), 'blocked-provider-owner-unknown')
            with self.assertRaisesRegex(Refused, 'ownership unsettled'):
                host.advance(binding(), host.owner)
            with self.assertRaisesRegex(Refused, 'ownership unsettled'):
                host.retire(binding(), cancelled=True)
            self.assertEqual(host.recover(binding(2, 2, 2)), 'requeue')
            with self.assertRaisesRegex(Refused, 'capacity'):
                host.promote(binding(2, 2, 2))
            self.assertEqual(host.current(host.owner)['generations']['2']['provider_starts'], 0)
            host.recover(binding(), provider_settled=True)
            host.advance(binding(), host.owner, terminal=True)
            host.promote(binding(3, 3, 3))  # Deliberately no historical FIFO guarantee.
            self.assertEqual(host.advance(binding(3, 3, 3), host.owner)['seq'], 0)

    def test_call_receipt_is_not_an_effect(self):
        with Controller(self.root) as host:
            host.begin(binding())
            event = host.advance(binding(), host.owner, call=True)
            host.receipt(binding(), event['seq'])
            effects = Effects(self.root)
            self.assertEqual(effects.read()['counter'], 0)
            self.assertEqual(effects.read()['calls'], {})
        # A client could execute after receipt, but no receipt proves it did.
        result = self.child('effect', 'after-effect')
        self.assertEqual(result.returncode, 86)
        effects = Effects(self.root)
        self.assertEqual(effects.read()['counter'], 1)
        self.assertEqual(effects.read()['calls']['1:0']['state'], 'unknown')
        result = self.child('effect')
        self.assertEqual(result.returncode, 2)
        self.assertIn('outcome unknown', result.stdout)
        self.assertEqual(effects.read()['counter'], 1)

    def test_known_call_result_replays_without_counter_increment(self):
        first = self.child('effect')
        self.assertEqual(first.returncode, 0)
        second = self.child('effect')
        self.assertEqual(second.returncode, 0)
        self.assertEqual(json.loads(first.stdout), json.loads(second.stdout))
        self.assertEqual(Effects(self.root).read()['counter'], 1)

    def test_binding_mismatch_cancellation_expiry_and_cleanup(self):
        with Controller(self.root) as host:
            host.begin(binding())
            host.advance(binding(), host.owner)
            for wrong in (binding(request=2), binding(revision='fake-v2'), binding(session=2)):
                with self.assertRaisesRegex(Refused, 'mismatch'):
                    host.recover(wrong)
                with self.assertRaisesRegex(Refused, 'mismatch'):
                    host.begin(wrong)
            host.retire(binding(), cancelled=True)
            self.assertEqual(host.recover(binding()), 'cancelled')
            item = host.current(host.owner)['generations']['1']
            self.assertIsNone(item['checkpoint'])
            self.assertEqual(item['events'], [])
            self.assertEqual(host.begin(binding()), 'duplicate-cancelled')
            host.begin(binding(2, 2, 2))
            with self.assertRaisesRegex(Refused, 'expired'):
                host.recover(binding(2, 2, 2), now=900)
            host.retire(binding(2, 2, 2), now=900)
            with self.assertRaisesRegex(Refused, 'expired'):
                host.begin(binding(2, 2, 2), now=900)
        for path in self.root.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.unlink()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_incompatible_incomplete_and_oversized_records(self):
        with Controller(self.root) as host:
            host.begin(binding())
        target = self.root / 'host.json'
        original = target.read_bytes()
        for raw in (original[:len(original) // 2], original.replace(b'fake-v1', b'fake-v9')):
            target.write_bytes(raw)
            with self.assertRaises(Refused):
                Controller(self.root)
            self.assertEqual(target.read_bytes(), raw)
        target.write_bytes(b'x' * 65)
        with patch('probe.MAX_RECORD', 64):
            with self.assertRaisesRegex(Refused, 'too large'):
                Controller(self.root)
        self.assertEqual(target.read_bytes(), b'x' * 65)
        target.write_bytes(original)
        snapshot = Snapshot(self.root, 'host.json')
        item = snapshot.read()
        item['schema'] = 99
        snapshot.write(item)
        with self.assertRaisesRegex(Refused, 'incompatible'):
            Controller(self.root)
        target.unlink()
        (self.root / 'host.json.staged').write_bytes(b'incomplete')
        (self.root / 'host.json.staged').chmod(0o600)
        with self.assertRaisesRegex(Refused, 'incomplete initial'):
            Controller(self.root)

    def test_snapshot_bound_and_client_gap_or_replacement(self):
        with self.assertRaisesRegex(Refused, 'too large'):
            Snapshot(self.root, 'bounded.json').write({'value': 'x' * MAX_RECORD})
        self.assertFalse((self.root / 'bounded.json').exists())
        client = Client()
        with self.assertRaisesRegex(Refused, 'gap'):
            client.receive(dict(seq=1, kind='integer', value=1))
        event = dict(seq=0, kind='integer', value=0)
        client.receive(event)
        with self.assertRaisesRegex(Refused, 'replacement'):
            client.receive(dict(seq=0, kind='integer', value=9))
        self.assertFalse(client.receive(copy.deepcopy(event)))


if __name__ == '__main__':
    unittest.main()
