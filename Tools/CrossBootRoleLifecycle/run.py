#!/usr/bin/env python3
import argparse,base64,io,json,os,re,shutil,stat,sys,tarfile,traceback
from pathlib import Path
sys.dont_write_bytecode=True
from vm import VM,sha,write

p=argparse.ArgumentParser(description='Qualify explicit original-role retirement across an actual disposable macOS cold boot.')
p.add_argument('--scratch',type=Path,required=True);p.add_argument('--label',required=True)
p.add_argument('--executable',type=Path,required=True);p.add_argument('--metallib',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True)
a=p.parse_args();base=a.scratch.resolve(strict=True)
assert str(base).startswith('/private/tmp/reach-s98.') and base.stat().st_uid==os.getuid() and stat.S_IMODE(base.stat().st_mode)==0o700
assert re.fullmatch('[a-z0-9-]+',a.label)
root=base/('qualification-'+a.label);root.mkdir(mode=0o700);(root/'bin').mkdir(mode=0o700)
shutil.copyfile(a.executable,root/'bin/reachd');(root/'bin/reachd').chmod(0o700)
shutil.copyfile(a.metallib,root/'bin/mlx.metallib');(root/'bin/mlx.metallib').chmod(0o600)
vm=VM(root,'reach-s98-'+base.name.split('.',1)[1].replace('_','-')+'-'+a.label)
outcome={'result':'RUNNING','vm':vm.name,'guest':vm.guest,'executableSHA256':sha(root/'bin/reachd'),'metalSHA256':sha(root/'bin/mlx.metallib')}
write(vm.e/'inputs.json',{'executable':{'source':str(a.executable),'sha256':outcome['executableSHA256']},'metallib':{'source':str(a.metallib),'sha256':outcome['metalSHA256']},'fixtures':{str(f.relative_to(a.fixtures)):sha(f) for f in a.fixtures.rglob('*') if f.is_file()}})
def guest(mode):
 profile='(version 1)(allow default)(deny network*)'
 if mode!='initialize':
  for role in ['host','client']:profile+=' (deny file-read-data (literal "'+vm.guest+'/roots/'+role+'/bootstrap/'+role+'/current"))'
 args=['/usr/bin/sandbox-exec','-p',profile,'/usr/bin/python3',vm.guest+'/guest.py',mode,vm.guest]
 return vm.user_exec('guest-'+mode,args,timeout=180)
def collect(label):
 _,data,_=vm.user_exec(label,['/usr/bin/tar','-cf','-','-C',vm.guest,'evidence','logs','controls'],timeout=30)
 target=root/'guest';target.mkdir(mode=0o700,exist_ok=True)
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
  for member in archive:
   path=Path(member.name)
   assert not path.is_absolute() and '..' not in path.parts and path.parts[0] in ['evidence','logs','controls']
   assert member.isdir() or member.isfile()
   dest=target/path
   if member.isdir():dest.mkdir(parents=True,mode=0o700,exist_ok=True)
   else:
    dest.parent.mkdir(parents=True,mode=0o700,exist_ok=True);dest.write_bytes(archive.extractfile(member).read());dest.chmod(0o600)
try:
 vm.clone();vm.start('boot-1')
 vm.rpc('prepare-owned-guest',f'''set -eu
[[ $EUID == 0 ]]
[[ $(/usr/bin/stat -f %u /Users/threshold-auto) == 503 ]]
[[ ! -e {vm.guest} && ! -L {vm.guest} ]]
/bin/mkdir -m 700 {vm.guest}
/usr/sbin/chown 503:20 {vm.guest}
''')
 bundle=root/'fixture-transfer.tar'
 with tarfile.open(bundle,'w') as archive:
  files=[(root/'bin/reachd','bin/reachd',0o700),(root/'bin/mlx.metallib','bin/mlx.metallib',0o600),(Path(__file__).with_name('guest.py'),'guest.py',0o600),(a.fixtures/'public-model.json','public-model.json',0o600)]
  files += [(f,'model/'+str(f.relative_to(a.fixtures/'model')),0o600) for f in sorted((a.fixtures/'model').rglob('*')) if f.is_file()]
  for source,name,mode in files:
   info=archive.gettarinfo(str(source),arcname=name);info.mode=mode;info.uid=503;info.gid=20;info.uname='threshold-auto';info.gname='staff'
   with source.open('rb') as content:archive.addfile(info,content)
 assert bundle.stat().st_size<=3<<30
 vm.user_exec('transfer-owned-fixture',['/usr/bin/tar','-xf','-','-C',vm.guest],body=bundle.read_bytes(),timeout=60)
 vm.rpc('private-fixture-parents',f'''set -eu
[[ $EUID == 503 ]]
/bin/chmod 700 {vm.guest}/bin {vm.guest}/model
/usr/bin/shasum -a 256 {vm.guest}/bin/reachd {vm.guest}/bin/mlx.metallib
''',user=True)
 guest('initialize');collect('collect-original-public-evidence')
 vm.stop('first-stop');vm.start('boot-2')
 guest('postboot');collect('collect-postboot-public-evidence')
 d=json.loads((root/'guest/evidence/campaign.json').read_text());assert d['result']=='PASS' and d['bootChanged']
 # Transfer only recorded public evidence for in-guest comparison with caller inputs.
 vm.save();corpus=b'\n'.join(f.read_bytes() for folder in [vm.e,root/'guest'] for f in sorted(folder.rglob('*')) if f.is_file())
 assert len(corpus)<=8<<20
 vm.user_exec('transfer-evidence-corpus',['/usr/bin/tee',vm.guest+'/recorded-evidence.txt'],body=corpus,timeout=30)
 guest('scan');collect('collect-final-public-evidence')
 d=json.loads((root/'guest/evidence/campaign.json').read_text());assert d['callerInputsRemoved'] and all(v['joined'] for v in d['processes'])
 vm.rpc('remove-owned-guest-material',f'''set -eu
[[ $EUID == 503 ]]
[[ -d {vm.guest} && ! -L {vm.guest} ]]
[[ ! -e {vm.guest}/roots/host && ! -e {vm.guest}/roots/client && ! -e {vm.guest}/secrets ]]
[[ $(/usr/bin/stat -f %u {vm.guest}) == 503 ]]
/bin/rm -rf {vm.guest}
[[ ! -e {vm.guest} && ! -L {vm.guest} ]]
print OWNED_GUEST_MATERIAL_ABSENT
''',user=True)
 vm.stop('final-stop');vm.dispose()
 bundle.unlink();shutil.rmtree(root/'bin')
 outcome.update(result='PASS',bothOriginalRolesRetired=True,actualPostDeleteFreshRetry=True,guestFixtureAbsent=True,ownedCloneAbsent=True,callerInputsRemoved=True,knownGuestChildren=len(d['processes']))
except BaseException as error:
 outcome.update(result='FAIL',failure=str(error),traceback=traceback.format_exc())
 try:
  if vm.boot is not None:collect('collect-failure-public-evidence')
 except BaseException as collection:outcome['collectionFailure']=str(collection)
 raise
finally:
 if vm.boot is not None:
  try:vm.stop('failure-stop')
  except BaseException as stop:outcome['stopFailure']=str(stop)
 vm.sample();vm.save()
 outcome.update(knownHostChildren=len(vm.children),allKnownHostChildrenJoined=all(v['joined'] for v in vm.children),clonePresent=vm.target.exists(),ownedBootLive=vm.boot is not None,
  resourceObservation='Sampled whole-volume free-space delta is not exclusive APFS clone allocation. No exhaustive boot packet or opaque-descendant history is claimed.')
 write(root/'RESULT.json',outcome);print(json.dumps(outcome,sort_keys=True),flush=True)
