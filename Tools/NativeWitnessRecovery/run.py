#!/usr/bin/env python3
"""S107: one disposable guest, direct local witness, fresh receiver continuation."""
import argparse,hashlib,io,json,os,re,select,shutil,stat,subprocess,sys,tarfile,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
PRODUCT=Path(__file__).resolve().parent
sys.path.insert(0,str(PRODUCT.parent/'CrossBootRoleLifecycle'))
from vm import VM,TART,sha,write
parser=argparse.ArgumentParser(description=__doc__)
for name in ['scratch','fixtures','executable','service','metallib','retain','opening-baseline']:parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--baseline-free',type=int,required=True)
parser.add_argument('--label',required=True)
parser.add_argument('--campaign',choices=['full','loss','retirement'],default='full')
a=parser.parse_args();base=a.scratch.resolve(strict=True);fixtures=a.fixtures.resolve(strict=True)
assert str(base).startswith('/private/tmp/reach-s107.') and base.stat().st_uid==os.getuid() and stat.S_IMODE(base.stat().st_mode)==0o700
assert str(fixtures).startswith('/private/tmp/reach-s93.s107.') and fixtures.name=='fixtures'
assert re.fullmatch('[a-z0-9-]+',a.label)
root=base/('native-'+a.label);root.mkdir(mode=0o700)
rig=json.loads(a.opening_baseline.read_bytes())['rigInputs']
def raw(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def allocation(folder):
    total=0
    for p in folder.rglob('*'):
        try:total+=p.lstat().st_blocks*512
        except FileNotFoundError:pass
    return total
class NativeVM(VM):
    def __init__(self,*args):
        self.guestAllocated=0;self.guestFixtures=0;self.events={};self.phaseResults={};self.buffers={}
        super().__init__(*args)
    def baseline(self,label):
        super().baseline(label)
        assert all(sha(path)==value['expectedSHA256'] for path,value in rig.items())
        write(self.e/('s107-rig-'+label+'.json'),rig)
    def sample(self):
        super().sample()
        owned=sum(allocation(p) for p in [base,fixtures.parent,a.retain]);fixture=allocation(fixtures.parent)
        charge=max(owned,a.baseline_free-self.samples[-1]['freeBytes'])
        self.samples[-1].update(aggregateOwnedAllocatedBytes=owned+self.guestAllocated,fixtureAllocatedBytes=fixture+self.guestFixtures,additionalVolumeCharge=charge)
        assert charge<=20<<30 and owned+self.guestAllocated<=32<<30 and fixture+self.guestFixtures<=3<<30
        assert allocation(a.retain)<=1<<30
    def frame(self,p,timeout=300):
        end=time.monotonic()+timeout;buf=self.buffers.pop(p.pid,b'')
        while b'\n' not in buf:
            remaining=end-time.monotonic();assert remaining>0,'guest frame timeout'
            ready,_,_=select.select([p.stdout],[],[],min(remaining,5));self.sample()
            if not ready:continue
            part=os.read(p.stdout.fileno(),4096)
            if not part:assert not buf;return None
            buf+=part;assert len(buf.split(b'\n',1)[0])<=65536
        line,rest=buf.split(b'\n',1);self.buffers[p.pid]=rest;value=json.loads(line);assert raw(value)==line
        with (self.e/'protocol.log').open('ab') as log:log.write(line+b'\n');assert log.tell()<=192<<20
        return value
    def phase(self,phase):
        # The supervisor uses the existing Tart control pipe. Apply each complete
        # sandbox exactly once to service/receiver children, including read denials.
        cmd=[str(TART),'exec','-i',self.name,'/bin/launchctl','asuser','503','/usr/bin/sudo','-H','-u','threshold-auto','/usr/bin/python3',self.guest+'/guest.py',self.guest,phase]
        err=(self.e/(phase+'.stderr.log')).open('xb');started=time.monotonic()
        p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,env=self.env)
        self.commands.append(dict(label=phase,command=cmd));failure=None
        try:
            while True:
                assert time.monotonic()-started<1200
                value=self.frame(p)
                if value is None:break
                resources=value['resources'];self.guestAllocated=resources['guestAllocatedBytes'];self.guestFixtures=resources['guestFixtureAllocatedBytes'];self.sample()
                kind=value['kind']
                if kind=='event':
                    name=value['name'];assert re.fullmatch('[a-z0-9-]+',name)
                    self.events[name]=value['evidence'];write(self.e/(name+'.json'),value['evidence']);print('EARNED '+name,flush=True)
                elif kind=='phase-result':self.phaseResults[phase]=value['evidence']
                elif kind!='heartbeat':raise ValueError('unselected controller message; authority relay is prohibited')
                p.stdin.write(raw(dict(kind='ack'))+b'\n');p.stdin.flush()
            code=p.wait(timeout=15);assert code==0 and self.phaseResults[phase]['result']=='PASS',phase+' failed; inspect guest report'
        except BaseException as error:
            failure=str(error)
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
            raise
        finally:
            err.close();p.stdin.close();p.stdout.close()
            self.children.append(dict(label=phase,pid=p.pid,exitCode=p.returncode,joined=True,failure=failure,seconds=time.monotonic()-started));self.sample();self.save()
vm=NativeVM(root,'reach-s107-'+base.name.split('.',1)[1]+'-'+a.label)
result=dict(result='RUNNING',campaign=a.campaign,scope={'full':'full native socket campaign','loss':'fresh active loss and available replacement only','retirement':'original-role retirement and unrelated sentinel only'}[a.campaign],vm=vm.name,guest=vm.guest,noOSReboot=True,directGuestSocket=True)
write(root/'inputs.json',dict(executableSHA256=sha(a.executable),serviceSHA256=sha(a.service),metallibSHA256=sha(a.metallib),sources={p.name:sha(p) for p in PRODUCT.glob('*.py')},existingVMRecipeSHA256=sha(PRODUCT.parent/'CrossBootRoleLifecycle/vm.py'),fixtureSHA256={str(p.relative_to(fixtures)):sha(p) for p in fixtures.rglob('*') if p.is_file()},initialFreeBeforeCacheCopy=a.baseline_free))
payload=False;clean=False

def collect(label):
    _,data,_=vm.user_exec(label,['/usr/bin/tar','-cf','-','-C',vm.guest,'guest.py','control','logs','reports','originals','services'],timeout=30)
    assert len(data)<192<<20;destination=root/'guest';destination.mkdir(mode=0o700,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for member in archive:
            p=Path(member.name);assert not p.is_absolute() and '..' not in p.parts and (member.isdir() or member.isfile())
            target=destination/p
            if member.isdir():target.mkdir(exist_ok=True,parents=True,mode=0o700)
            else:
                assert member.size<=192<<20;target.parent.mkdir(exist_ok=True,parents=True,mode=0o700)
                target.write_bytes(archive.extractfile(member).read());target.chmod(0o600)
try:
    vm.clone();vm.start('s107-initial-boot')
    vm.rpc('prepare-owned-guest','set -eu\n[[ $EUID == 0 ]]\n[[ ! -e '+vm.guest+' && ! -L '+vm.guest+' ]]\n/bin/mkdir -m 700 '+vm.guest+'\n/usr/sbin/chown 503:20 '+vm.guest+'\n')
    bundle=root/'payload.tar'
    with tarfile.open(bundle,'w') as archive:
        files=[(a.executable,'bin/reachd',0o700),(a.service,'bin/witness-access-qualification',0o700),(a.metallib,'bin/mlx.metallib',0o600),(PRODUCT/'guest.py','guest.py',0o600)]
        files += [(p,'fixtures/'+str(p.relative_to(fixtures)),0o600) for p in fixtures.rglob('*') if p.is_file()]
        for source,name,mode in files:
            info=archive.gettarinfo(str(source),arcname=name);info.uid=503;info.gid=20;info.mode=mode
            with source.open('rb') as data:archive.addfile(info,data)
    vm.user_exec('transfer-owned-payload',['/usr/bin/tar','-xf','-','-C',vm.guest],body=bundle.read_bytes(),timeout=60);payload=True
    vm.rpc('private-parents','set -eu\n[[ $EUID == 503 ]]\n/bin/chmod 700 '+vm.guest+'/bin '+vm.guest+'/fixtures '+vm.guest+'/fixtures/model '+vm.guest+'/fixtures/requests\n',user=True)
    vm.phase('campaign' if a.campaign=='full' else a.campaign);result['result']='PASS'
except BaseException as error:result.update(result='FAIL',failure=str(error),traceback=traceback.format_exc())
finally:
    if vm.boot is not None and payload:
        phase=vm.phaseResults.get('campaign' if a.campaign=='full' else a.campaign,{})
        clean=phase.get('retirementComplete',False) and phase.get('knownWorkersJoined',False) and not phase.get('rootObservations') and not phase.get('keychainPaths') and phase.get('secretsAbsent',False)
        attempt=0
        while not clean:
            attempt+=1
            try:
                cleanupPhase='cleanup-'+str(attempt);vm.phase(cleanupPhase);phase=vm.phaseResults[cleanupPhase]
                clean=phase['retirementComplete'] and phase['knownWorkersJoined'] and not phase['rootObservations'] and not phase['keychainPaths'] and phase['secretsAbsent'];assert clean
            except BaseException as error:
                result.setdefault('cleanupFailures',[]).append(str(error));result['result']='FAIL'
                write(root/'cleanup-owner-retained.json',result)
                try:collect('failed-cleanup-'+str(attempt))
                except BaseException as collection:result['collectionFailure']=str(collection)
                print('CLEANUP OWNER RETAINED; bounded repair can signal '+str(root/'retry-cleanup'),flush=True)
                retry=root/'retry-cleanup'
                while not retry.exists():vm.sample();time.sleep(5)
                info=retry.lstat();assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and retry.read_bytes()==b'retry\n';retry.unlink()
        try:collect('collect-final')
        except BaseException as error:result['collectionFailure']=str(error)
    elif not payload:clean=True
    if clean:
        if vm.boot is not None:
            try:
                if payload:vm.rpc('remove-owned-payload','set -eu\n[[ $EUID == 503 ]]\n[[ -d '+vm.guest+' && ! -L '+vm.guest+' ]]\n[[ $(/usr/bin/stat -f %u '+vm.guest+') == 503 ]]\n/bin/rm -rf '+vm.guest+'\n[[ ! -e '+vm.guest+' && ! -L '+vm.guest+' ]]\nprint OWNED_PAYLOAD_ABSENT\n',user=True)
                vm.stop('s107-final-stop')
            except BaseException as error:result['stopFailure']=str(error)
        if vm.boot is None and vm.target.exists():
            try:vm.dispose()
            except BaseException as error:result['disposalFailure']=str(error)
    vm.sample();vm.save()
    result.update(productRetirement=clean,clonePresent=vm.target.exists(),ownedBootLive=vm.boot is not None,knownHostChildrenJoined=all(x['joined'] for x in vm.children),phases=vm.phaseResults,resourceObservation='Sampled owned allocation and whole-volume free delta; no exclusive COW or exhaustive opaque descendant claim.')
    if result['result']=='PASS' and (not clean or vm.target.exists() or any(k.endswith('Failure') for k in result)):result['result']='FAIL'
    write(root/'RESULT.json',result)
    retained=a.retain.resolve(strict=True)/root.name;retained.mkdir(mode=0o700)
    for name in ['evidence','guest']:
        if (root/name).exists():shutil.copytree(root/name,retained/name)
    for name in ['RESULT.json','inputs.json']:shutil.copyfile(root/name,retained/name)
    assert sum(p.stat().st_size for p in a.retain.rglob('*') if p.is_file())<=1<<30
    print(json.dumps(result,sort_keys=True),flush=True)
sys.exit(0 if result['result']=='PASS' else 1)
