#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
for script in build-linux-connector.sh package-linux-connector.sh linux-connector-static-test.sh; do sh -n "$root/scripts/$script"; done
for script in postinst prerm postrm; do sh -n "$root/Linux/connector/package/DEBIAN/$script"; done
python3 - "$root" <<'PY'
from pathlib import Path
import json,re,sys
root=Path(sys.argv[1]);p=root/'Linux/connector/package';unit=(p/'usr/lib/systemd/system/reach-exo-connector.service').read_text()
required=['Type=notify','NotifyAccess=main','User=reach-exo-connector','Group=reach-exo-connector','RestartPreventExitStatus=64','StartLimitBurst=3','StartLimitIntervalSec=60s','RestartSec=2s','TimeoutStartSec=10s','TimeoutStopSec=5s','NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=','ProtectSystem=strict','RuntimeDirectory=reach-exo-connector','MemoryMax=256M','TasksMax=128','LimitNOFILE=1024']
assert all(line in unit.splitlines() for line in required)
example=json.loads((p/'usr/share/doc/reach-exo-connector/connector.example.json').read_text())
assert example['schema_version']==1 and example['listen_address']=='127.0.0.1:52415' and example['server_name']=='reach-exo-gateway'
assert all(v.startswith('/etc/reach-exo-connector/') for v in example['tls'].values())
ordering=(p/'usr/share/doc/reach-exo-connector/reachd-ordering.conf').read_text()
assert 'Wants=reach-exo-connector.service' in ordering and 'After=reach-exo-connector.service' in ordering
assert 'BindsTo=' not in ordering and 'PartOf=' not in ordering
postinst=(p/'DEBIAN/postinst').read_text()
assert not re.search(r'\b(curl|wget)\b|systemctl\s+(enable|start|restart|preset)\b',postinst)
for name in ['prerm','postrm']:
 s=(p/'DEBIAN'/name).read_text()
 assert 'userdel' not in s and 'groupdel' not in s and 'reachd.service.d' not in s
 assert not re.search(r'rm[^\n]*/etc/',s)
assert not any(x.suffix in ['.pem','.deb','.gz','.safetensors'] for x in p.rglob('*'))
for x in (root/'internal/connectorservice').glob('*.go'):
 assert x.read_text().startswith('//go:build linux\n')
print('Linux connector source/package contracts: PASS')
PY
