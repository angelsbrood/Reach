#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
sh -n "$script_dir/build-bootstrap.sh"
sh -n "$script_dir/bootstrap-static-test.sh"
python3 - "$root" <<'PY'
from pathlib import Path
import os,subprocess,sys,tempfile
root=Path(sys.argv[1]).resolve();build=root/'scripts/build-bootstrap.sh'
with tempfile.TemporaryDirectory(prefix='bootstrap-guards-') as tmp:
 scratch=Path(tmp).resolve();alias=scratch/'checkout-alias';alias.symlink_to(root.parent,target_is_directory=True)
 fake=scratch/'bin';fake.mkdir();marker=scratch/'go-called'
 (fake/'go').write_text('#!/bin/sh\nprintf called > "'+str(marker)+'"\nprintf go1.99.0\\n\n');(fake/'go').chmod(0o755)
 env=dict(os.environ,PATH=str(fake)+os.pathsep+os.environ['PATH'])
 cases=[([], 'usage:'),(['windows',str(scratch/'out')],'target must'),(['linux/amd64',str(scratch/'out')],'target must'),(['linux','relative'],'must be absolute'),(['darwin',str(root/'out')],'outside the checkout'),(['linux',str(root.parent/'out')],'outside the checkout'),(['linux',str(alias/'new/out')],'outside the checkout')]
 for args,message in cases:
  result=subprocess.run(['sh',str(build),*args],env=env,capture_output=True,text=True)
  assert result.returncode!=0 and message in result.stderr,(args,result)
  assert not marker.exists(),'invalid target/output reached Go'
 for target in ['linux','darwin']:
  result=subprocess.run(['sh',str(build),target,str(scratch/'out')],env=env,capture_output=True,text=True)
  assert result.returncode!=0 and 'Go 1.26.5 is required' in result.stderr,result
  assert marker.exists() and not (scratch/'out').exists(),'wrong Go version mutated output'
print('Bootstrap target/output/alias/toolchain guards: PASS')
PY
