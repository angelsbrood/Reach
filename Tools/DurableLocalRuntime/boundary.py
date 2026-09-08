"""Explicitly selected disposable state only; no test controls in runtime input."""
import json
import os
import signal


def run(campaign):
    for route in ['zero', 'short', 'lazy']:
        with campaign.root(route) as root:
            report = campaign.report(route)
            campaign.command(route + '-begin', ['durable-local', 'begin', '--root', str(root), '--request', str(campaign.requests / (route + '.json')), '--report', str(report)], expected=1 if route == 'lazy' else 0)
            value = json.loads(report.read_text())
            if route == 'lazy':
                assert value['stage'] == 'error' and not value['terminal'] and value['inbox'] == []
                assert value['traces'][0]['kind'] == 'probe' and value['traces'][0]['calls'] > 0
                assert value['traces'][-1]['kind'] == 'schema' and value['traces'][-1]['calls'] == 0
            else:
                assert value['terminal'] and 'error' in value['providerEnding']
                if route == 'zero':
                    assert value['nativeCalls'] == 0
            campaign.evidence['cells'].append(dict(route=route, terminal=value['terminal'], nativeCalls=value['nativeCalls'], providerEnding=value.get('providerEnding')))
        campaign.save()
        print(route + ' passed', flush=True)
    with campaign.root('boundaries') as root:
        campaign.command('reused-init', ['durable-local', 'init', '--root', str(root), '--model', str(campaign.model)], expected=1)
        unsafe = campaign.path / 'roots/unsafe'
        unsafe.mkdir(mode=0o755)
        try:
            campaign.command('unsafe-init', ['durable-local', 'init', '--root', str(unsafe), '--model', str(campaign.model)], expected=1)
        finally:
            unsafe.rmdir()
        for name, source in [('incomplete', root / 'bootstrap/ready.json'), ('missing-keychain', root / 'keys/local.keychain-db')]:
            held = campaign.path / 'roots' / ('held-' + name)
            source.rename(held)
            try:
                campaign.refusal(name, root)
            finally:
                held.rename(source)
        source = root / 'keys/local.keychain-db'
        held = campaign.path / 'roots/held-replaced'
        source.rename(held)
        try:
            fd = os.open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, b'invalid replacement')
            finally:
                os.close(fd)
            campaign.refusal('replaced-keychain', root)
        finally:
            source.unlink()
            held.rename(source)
        worker = campaign.child('contention-begin', ['durable-local', 'begin', '--root', str(root), '--request', str(campaign.requests / 'ordinary.json'), '--progress'])
        try:
            assert worker.until(lambda value: value.get('nativeCalls', 0) >= 8 and not value.get('terminal', True))
            worker.process.send_signal(signal.SIGSTOP)
            campaign.refusal('active-owner-refuses', root)
        finally:
            worker.kill()
        report = campaign.report('cancel')
        campaign.command('cancel', ['durable-local', 'cancel', '--root', str(root), '--report', str(report)])
        value = json.loads(report.read_text())
        assert value['stage'] == 'cancelled' and not value['terminal'] and value.get('providerEnding') is None
        assert value['nativeCalls'] == 0 and value['disposition'] == 'cancelled' and value['beforeInbox'] == value['inbox']
        campaign.refusal('retired-recovery', root)
        # Exact newly created container only, with no unlock or credential query.
        campaign.command('lock-owned-keychain', ['/usr/bin/security', 'lock-keychain', str(source)], external=True)
        campaign.refusal('locked-keychain', root)
        campaign.evidence['cells'].append(dict(route='boundaries', cases=['reused', 'unsafe', 'incomplete', 'missing', 'replaced', 'contended', 'joined-death-cancel', 'retired', 'locked'], cancelDisposition=value['disposition'], unchangedInbox=True))
    campaign.save()
    print('boundaries passed', flush=True)
