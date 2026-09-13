#!/usr/bin/env python3
"""S100 owned-guest normal native feasibility. No postboot-native claim."""
import argparse,hashlib,io,json,os,re,shutil,stat,sys,tarfile,traceback
from pathlib import Path
sys.dont_write_bytecode=True
PRODUCT=Path(__file__).resolve().parent
sys.path.insert(0,str(PRODUCT.parent/'CrossBootRoleLifecycle'))
from vm import VM,sha,write
BINDINGS={
'/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/shared/current-baseline.json':'e2e97d565f2d644753fd7680e07f18368110816dde9ba69ab324b13f0331dea9',
'/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/os-maintenance-0913/qualification.json':'22ac4e0686fe3da837162e2b74a5bc52a59cf3616534d96cb3acc2f18ce9eb75',
'/Users/nellymoon/.codex/visualizations/2026/09/05/01a07338-c854-74e3-8201-51c76300ba95/threshold-vm-runner/rpc-maintenance-0907/threshold-tart-guest-agent':'e520451185ec1ec64727d317ac6733ab33b80acec8b361f49250269f8ac4f7ab'}
parser=argparse.ArgumentParser(description=__doc__)
for n in ['scratch','fixtures','executable','metallib','retain']:parser.add_argument('--'+n,type=Path,required=True)
parser.add_argument('--label',required=True)
a=parser.parse_args();base=a.scratch.resolve(strict=True);fixtures=a.fixtures.resolve(strict=True)
assert str(base).startswith('/private/tmp/reach-s100.') and base.stat().st_uid==os.getuid() and stat.S_IMODE(base.stat().st_mode)==0o700
assert str(fixtures).startswith('/private/tmp/reach-s93.s100.') and fixtures.name=='fixtures'
assert re.fullmatch('[a-z0-9-]+',a.label)
root=base/('native-'+a.label);root.mkdir(mode=0o700)

class NativeVM(VM):
    def baseline(self,label):
        super().baseline(label)
        assert all(sha(p)==h for p,h in BINDINGS.items()),'current selected S100 rig inputs'
        write(self.e/('s100-rig-'+label+'.json'),BINDINGS)
    def sample(self):
        super().sample()
        allocated=0
        for folder in [base,fixtures.parent]:
            for p in folder.rglob('*'):
                try:allocated+=p.lstat().st_blocks*512
                except FileNotFoundError:pass
        fixtureBytes=sum(p.lstat().st_blocks*512 for p in fixtures.parent.rglob('*'))
        self.samples[-1].update(aggregateOwnedAllocatedBytes=allocated,fixtureAllocatedBytes=fixtureBytes)
        assert allocated<=32<<30 and fixtureBytes<=3<<30

vm=NativeVM(root,'reach-s100-'+base.name.split('.',1)[1]+'-native-'+a.label)
vm.guest='/private/tmp/reach-s100.'+base.name.split('.',1)[1]+'-native-'+a.label
result={'result':'RUNNING','scope':'ordinary same-boot native feasibility only','vm':vm.name,'guest':vm.guest}
write(root/'inputs.json',{'executable':str(a.executable),'executableSHA256':sha(a.executable),'metallib':str(a.metallib),'metallibSHA256':sha(a.metallib),
 'fixtures':{str(p.relative_to(fixtures)):sha(p) for p in fixtures.rglob('*') if p.is_file()},
 'newRunner':{p.name:sha(p) for p in PRODUCT.glob('*.py')},
 'existingNativeCellsSHA256':sha(PRODUCT.parent/'DurableLocalRuntime/native.py'),
 'existingLocalSupervisorSHA256':sha(PRODUCT.parent/'DurableLocalRuntime/run.py'),
 'existingVMRecipeSHA256':sha(PRODUCT.parent/'CrossBootRoleLifecycle/vm.py')})
guardian=True;smokeStarted=False

def collect(label):
    _,data,_=vm.user_exec(label,['/usr/bin/tar','-cf','-','--exclude=bin','--exclude=fixtures','--exclude=existing-local-runner','--exclude=roots','-C',vm.guest,'.'],timeout=30)
    assert len(data)<192<<20
    destination=root/'guest';destination.mkdir(exist_ok=True,mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for member in archive:
            p=Path(member.name);assert not p.is_absolute() and '..' not in p.parts and (member.isdir() or member.isfile())
            target=destination/p
            if member.isdir():target.mkdir(exist_ok=True,parents=True,mode=0o700)
            else:
                assert member.size<=192<<20
                target.parent.mkdir(exist_ok=True,parents=True,mode=0o700)
                target.write_bytes(archive.extractfile(member).read());target.chmod(0o600)
try:
    vm.clone();vm.start('native-boot')
    vm.rpc('prepare-owned-native-guest',f"""set -eu
[[ $EUID == 0 ]]
[[ ! -e {vm.guest} && ! -L {vm.guest} ]]
/bin/mkdir -m 700 {vm.guest}
/usr/sbin/chown 503:20 {vm.guest}
""")
    bundle=root/'payload.tar'
    with tarfile.open(bundle,'w') as archive:
        files=[(a.executable,'bin/reachd',0o700),(a.metallib,'bin/mlx.metallib',0o600),(PRODUCT/'native_guest.py','native_guest.py',0o600)]
        files += [(PRODUCT.parent/'DurableLocalRuntime'/n,'existing-local-runner/'+n,0o600) for n in ['run.py','native.py','boundary.py']]
        files += [(p,'fixtures/'+str(p.relative_to(fixtures)),0o600) for p in fixtures.rglob('*') if p.is_file()]
        for source,name,mode in files:
            info=archive.gettarinfo(str(source),arcname=name);info.uid=503;info.gid=20;info.mode=mode
            with source.open('rb') as data:archive.addfile(info,data)
    assert bundle.stat().st_size<=3<<30
    vm.user_exec('transfer-owned-native-payload',['/usr/bin/tar','-xf','-','-C',vm.guest],body=bundle.read_bytes(),timeout=60)
    vm.rpc('private-native-fixture-parents',f"""set -eu
[[ $EUID == 503 ]]
/bin/chmod 700 {vm.guest}/bin {vm.guest}/fixtures {vm.guest}/fixtures/model {vm.guest}/fixtures/requests {vm.guest}/existing-local-runner
/usr/bin/shasum -a 256 {vm.guest}/bin/reachd {vm.guest}/bin/mlx.metallib
""",user=True)
    vm.user_exec('guest-metal-device-observation',['/usr/bin/osascript','-l','JavaScript','-e','ObjC.import("Metal"); var d=$.MTLCopyAllDevices(); var n=Number(d.count); var names=[]; for(var i=0;i<n;i++){names.push(d.objectAtIndex(i).name.js);} JSON.stringify({deviceCount:n,names:names})'],allowFailure=True)
    smokeStarted=True
    code,_,_=vm.user_exec('ordinary-native-smoke',['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)','/usr/bin/python3',vm.guest+'/native_guest.py',vm.guest],timeout=480,allowFailure=True)
    collect('collect-native-evidence')
    evidence=json.loads((root/'guest/native-result.json').read_text())
    childEvidence=[json.loads(p.read_text()) for p in (root/'guest').glob('*/evidence.json')]
    guardian=bool(evidence.get('cleanupGuardianPID')) or bool(evidence.get('rootObservations')) or bool(evidence.get('keychainPaths')) or any(not c['joined'] for d in childEvidence for c in d['processes'])
    if guardian:
        result.update(result='BLOCK',cleanupGuardianPID=evidence.get('cleanupGuardianPID'),cleanupOwnerRetained=True)
        raise RuntimeError('Original cleanup creator remains available in owned guest')
    assert code==0 and evidence['result']=='PASS',evidence.get('failure','native smoke failed')
    assert not evidence['rootObservations'] and not evidence['keychainPaths']
    result.update(result='PASS',nativeGuestFeasibility='PASS',authorityOnlyReboot='NOT EXECUTED',sameBootOnly=True,
                  originalCreatorsRetired=True,positiveNativeCheckpoint=True,freshProcessContinuation=True,
                  zeroNativeTerminalReplay=True,uninterruptedReferenceMatched=True)
except BaseException as error:
    result.update(failure=str(error),traceback=traceback.format_exc())
    if result['result']=='RUNNING':result['result']='FAIL'
finally:
    if not smokeStarted:guardian=False
    if not guardian:
        if vm.boot is not None:
            try:
                if (root/'guest/native-result.json').exists():
                    # Failed early native construction may have created no root or Keychain.
                    v=json.loads((root/'guest/native-result.json').read_text())
                    result['productRootsAbsent']=not v.get('rootObservations')
                    result['productKeychainsAbsent']=not v.get('keychainPaths')
                vm.rpc('remove-owned-native-payload',f"""set -eu
[[ $EUID == 503 ]]
[[ -d {vm.guest} && ! -L {vm.guest} ]]
[[ $(/usr/bin/stat -f %u {vm.guest}) == 503 ]]
/bin/rm -rf {vm.guest}
[[ ! -e {vm.guest} && ! -L {vm.guest} ]]
print OWNED_NATIVE_PAYLOAD_ABSENT
""",user=True)
                vm.stop('native-final-stop')
            except BaseException as stop:result['stopFailure']=str(stop)
        if vm.boot is None and vm.target.exists():
            try:vm.dispose()
            except BaseException as disposal:result['disposalFailure']=str(disposal)
    vm.sample();vm.save()
    result.update(clonePresent=vm.target.exists(),ownedBootLive=vm.boot is not None,
                  knownHostChildren=len(vm.children),knownHostChildrenJoined=all(x['joined'] for x in vm.children),
                  resourceObservation='Sampled aggregate owned allocation and volume free-space delta; no exclusive COW allocation or exhaustive opaque descendant history claimed.')
    if result['result']=='PASS' and (result['clonePresent'] or result['ownedBootLive']):result['result']='FAIL'
    write(root/'RESULT.json',result)
    retained=a.retain.resolve(strict=True)/root.name;assert not retained.exists();retained.mkdir(mode=0o700)
    for name in ['evidence','guest']:
        if (root/name).exists():shutil.copytree(root/name,retained/name)
    for name in ['RESULT.json','inputs.json']:shutil.copyfile(root/name,retained/name)
    assert sum(p.stat().st_size for p in a.retain.rglob('*') if p.is_file())<=1<<30
    print(json.dumps(result,sort_keys=True),flush=True)
sys.exit(0 if result['result']=='PASS' else 1)
