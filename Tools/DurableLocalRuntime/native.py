"""Normal-executable death/recovery and uninterrupted reference cells."""
import json
from pathlib import Path
import signal


def run(campaign):
    for label, args in [('help', ['--help']), ('serve-help', ['serve', '--help']), ('durable-help', ['durable-local', '--help'])]:
        campaign.command(label, args)
    assert not list((campaign.path / 'roots').iterdir())
    for route in campaign.args.routes:
        with campaign.root(route) as root:
            report = campaign.report(route + '-recover')
            if campaign.args.mode == 'reference':
                campaign.command(route + '-reference', ['durable-local', 'begin', '--root', str(root), '--request', str(campaign.requests / (route + '.json')), '--report', str(report)])
                result = json.loads(report.read_text())
                prior = json.loads((Path(campaign.args.reference_dir) / (route + '-recover.json')).read_text())
                assert result['binding'] == prior['binding'] and result['inbox'] == prior['inbox'], (route, 'same-binding exact reference')
                assert result['terminal'] and result['requestPreparations'] == result['issues'] == result['begins'] == 1
                assert result['modelPrepares'] == 0 and result['traces'][0]['offsets'][0] == 0
                cut = {'uninterruptedReference': True}
            else:
                worker = campaign.child(route + '-begin', ['durable-local', 'begin', '--root', str(root), '--request', str(campaign.requests / (route + '.json')), '--progress'])
                try:
                    cut = worker.until(lambda value: value.get('nativeCalls', 0) >= 8 and not value.get('terminal', True))
                    assert cut, (route, 'no live cut')
                    worker.process.send_signal(signal.SIGSTOP)
                finally:
                    worker.kill()
                campaign.command(route + '-recover', ['durable-local', 'recover', '--root', str(root), '--report', str(report)])
                result = json.loads(report.read_text())
                assert result['terminal'] and result['nativeCalls'] > 0
                assert all(result[key] == 0 for key in ['modelPrepares', 'requestPreparations', 'templateCalls', 'requestTokenizations', 'issues', 'begins'])
                assert result['recoveries'] == 1 and result['traces'][0]['offsets'][0] > 0
                assert result['inbox'][:len(result['beforeInbox'])] == result['beforeInbox']
            replay = campaign.report(route + '-terminal')
            campaign.command(route + '-terminal', ['durable-local', 'recover', '--root', str(root), '--report', str(replay)])
            terminal = json.loads(replay.read_text())
            assert terminal['nativeCalls'] == 0 and terminal['inbox'] == result['inbox']
            assert terminal['binding'] == result['binding'] and terminal['accepted']['context'] == result['accepted']['context']
            campaign.evidence['cells'].append(dict(route=route, cut=cut, nativeCalls=result['nativeCalls'], high=result['high'], terminalReplay=True))
        campaign.evidence['cells'][-1]['retired'] = True
        campaign.save()
        print(route + ' passed', flush=True)
