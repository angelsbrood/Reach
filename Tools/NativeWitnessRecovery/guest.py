#!/usr/bin/env python3
"""S107 guest-owned direct-socket native recovery. No host certificate relay."""
import base64, hashlib, json, os, select, shutil, stat, subprocess, sys, time, traceback, uuid
from pathlib import Path
sys.dont_write_bytecode=True
if len(sys.argv)>1 and sys.argv[1]=='worker':
    selected=json.loads(base64.b64decode(sys.argv[2]));denied=[]
    for fd in selected.get('fds',[]):
        info=os.fstat(fd);assert info.st_uid==503 and stat.S_IMODE(info.st_mode)==0o600 and 32<=info.st_size<=128
    for path in selected['probes']:
        try:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);os.close(fd)
        except PermissionError:denied.append(path)
        else:raise AssertionError('required read denial missing')
    data=json.dumps(dict(stage='read-denial',paths=denied),sort_keys=True,separators=(',',':')).encode()
    sys.stdout.buffer.write(data+b'\n');sys.stdout.buffer.flush()
    os.execv(selected['command'][0],selected['command'])
BASE=Path(sys.argv[1]).resolve(strict=True);PHASE=sys.argv[2] if len(sys.argv)>2 else 'campaign'
assert str(BASE).startswith('/Users/threshold-auto/reach-s107-') and os.getuid()==503
assert BASE.stat().st_uid==503 and stat.S_IMODE(BASE.stat().st_mode)==0o700
os.umask(0o077)
for name in ['logs','reports','roots','control','secrets','originals','tmp','original-inputs','services','socket','other-socket']:
    (BASE/name).mkdir(exist_ok=True,mode=0o700)
EXE=BASE/'bin/reachd'; INPUTS=BASE/'original-inputs'
record=dict(phase=PHASE,wrapperPID=os.getpid(),processes=[],result='RUNNING')
def raw(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def write(p,x):p.write_bytes(raw(x)+b'\n');p.chmod(0o600)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save():write(BASE/'reports'/(PHASE+'.json'),record)
def allocation(root):
    return sum(p.lstat().st_blocks*512 for p in root.rglob('*'))
SENTINEL=BASE/'unrelated-retirement-sentinel'
sentinelRecord=BASE/'reports/retirement-sentinel.json'
if PHASE.startswith('cleanup'):
    assert SENTINEL.is_file() and sentinelRecord.is_file()
    sentinelDigest=json.loads(sentinelRecord.read_bytes())['sha256']
else:
    assert not SENTINEL.exists()
    SENTINEL.write_bytes(('unrelated to role roots: '+str(uuid.uuid4())+'\n').encode());SENTINEL.chmod(0o600)
    sentinelDigest=sha(SENTINEL);write(sentinelRecord,dict(path=str(SENTINEL),sha256=sentinelDigest,beforeOriginals=True))
def sentinel_check():
    assert SENTINEL.is_file() and not SENTINEL.is_symlink() and sha(SENTINEL)==sentinelDigest
    assert SENTINEL.stat().st_uid==503 and stat.S_IMODE(SENTINEL.stat().st_mode)==0o600
    return dict(path=str(SENTINEL),sha256=sentinelDigest,survivedOriginalRoleRetirement=True,disposal='later owned payload and clone disposal')
def controller(value):
    owned=allocation(BASE);fixture=allocation(BASE/'fixtures');free=shutil.disk_usage(BASE).free
    assert owned<=32<<30 and fixture<=3<<30 and free>=30<<30
    value=dict(value,resources=dict(guestAllocatedBytes=owned,guestFixtureAllocatedBytes=fixture,guestFreeBytes=free))
    data=raw(value);assert len(data)<=65536
    sys.stdout.buffer.write(data+b'\n');sys.stdout.buffer.flush()
    line=sys.stdin.buffer.readline(65538);assert line.endswith(b'\n') and len(line)<=65537;return json.loads(line)
def event(name,evidence):assert controller(dict(kind='event',name=name,evidence=evidence))=={'kind':'ack'}
def signed(x):return json.loads(base64.b64decode(json.loads(base64.b64decode(x))['body']))
def capture(args):
    started=time.monotonic();p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:out,err=p.communicate(timeout=30)
    except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=10);raise
    finally:
        record['processes'].append(dict(label='observation',pid=p.pid,command=args,exitCode=p.returncode,joined=True,seconds=time.monotonic()-started));save()
    (BASE/'logs'/('observation-'+str(p.pid)+'.stdout.log')).write_bytes(out)
    (BASE/'logs'/('observation-'+str(p.pid)+'.stderr.log')).write_bytes(err)
    assert p.returncode==0, 'observation failed '+str(p.pid)+': '+err.decode(errors='replace')[-1200:];return out
def boot():return capture(['/usr/sbin/sysctl','-n','kern.bootsessionuuid']).decode().strip().lower()
def metadata():return {flag:capture(['/usr/bin/security',flag,'-d','user']).decode() for flag in ['list-keychains','default-keychain']}
# Proven installed compiler selection; no native algorithm or compile disabling.
compiler='/Library/Developer/CommandLineTools/usr/bin/clang++';sdk='/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk'
launcher=BASE/'compiler-launcher';launcher.mkdir(exist_ok=True,mode=0o700);shim=launcher/'g++'
shimBytes=('#!/usr/bin/python3\nimport os,sys\nos.execv('+repr(compiler)+', ['+repr(compiler)+']+'+repr(['-no-canonical-prefixes','-isysroot',sdk,'-isystem',sdk+'/usr/include/c++/v1'])+'+sys.argv[1:])\n').encode()
if shim.exists():assert shim.read_bytes()==shimBytes
else:shim.write_bytes(shimBytes);shim.chmod(0o700)
os.environ['PATH']=str(launcher)+':'+str(Path(compiler).parent)+':'+os.environ.get('PATH','/usr/bin:/bin')
os.environ['TMPDIR']=str(BASE/'tmp');assert 'MLX_DISABLE_COMPILE' not in os.environ

ENDPOINT=str(BASE/'socket/s');assert len(ENDPOINT.encode())+1<=104
SERVICE=BASE/'bin/witness-access-qualification'
serviceOwner=None

def sandbox(denyInputs=False,denyModel=False,keychainDeny=True):
    p='(version 1)(allow default)(deny network*)'
    p+=''.join('(allow '+op+' (literal '+json.dumps(ENDPOINT)+'))' for op in ['network-bind','network-inbound','network-outbound'])
    if keychainDeny:p+='(deny file-read-data (subpath "/Users/threshold-auto/Library/Keychains"))'
    if denyInputs:p+='(deny file-read-data (subpath '+json.dumps(str(INPUTS))+') (subpath '+json.dumps(str(BASE/'fixtures/requests'))+'))'
    if denyModel:p+='(deny file-read-data (subpath '+json.dumps(str(BASE/'fixtures/model'))+'))'
    return p

def service_start(label,pairs):
    global serviceOwner
    assert serviceOwner is None
    root=BASE/'services'/label;root.mkdir(mode=0o700)
    selection=root/'selection.json';selection.write_bytes(raw(pairs));selection.chmod(0o600)
    descriptor=root/'descriptor.json'
    cmd=['/usr/bin/sandbox-exec','-p',sandbox(),str(SERVICE),'service','--endpoint',ENDPOINT,'--selection',str(selection),'--descriptor',str(descriptor)]
    log=(BASE/'logs'/(label+'-service.stderr.log')).open('xb')
    p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=log)
    item=dict(label=label+'-service',pid=p.pid,command=cmd,joined=False,started=time.monotonic());record['processes'].append(item)
    serviceOwner=(p,item,log);save()
    ready,_,_=select.select([p.stdout],[],[],10);assert ready
    line=p.stdout.readline(65538);assert len(line)<=65537 and line.endswith(b'\n');hello=json.loads(line)
    assert hello['stage']=='ready' and hello['pid']==p.pid and hello['descriptorSHA256']==sha(descriptor)
    item.update(descriptor=str(descriptor),descriptorSHA256=sha(descriptor),identity=json.loads(descriptor.read_bytes())['identity']);save()
    write(root/'started.json',item);return dict(item)

def service_stop():
    global serviceOwner
    if serviceOwner is None:return
    p,item,log=serviceOwner
    if p.poll() is None:p.terminate()
    try:code=p.wait(timeout=10)
    except subprocess.TimeoutExpired:p.kill();code=p.wait(timeout=10)
    item.update(exitCode=code,joined=True,seconds=time.monotonic()-item['started'])
    rest=p.stdout.read(65537);assert not rest;p.stdout.close();log.close();serviceOwner=None
    # Unlink only the joined issuer's endpoint in our private fixed socket root.
    endpoint=Path(ENDPOINT)
    if endpoint.exists():assert stat.S_ISSOCK(endpoint.lstat().st_mode);endpoint.unlink()
    save();return dict(item)

def selectionargs(pair):return ['--witness-descriptor',pair['descriptor'],'--witness-digest',pair['descriptorSHA256']]

def command(label,args,secret=None,pair=None,expected=0,checkpoint=False,boundary=None,denyInputs=False,denyModel=False):
    fds=[];args=list(map(str,args))
    if secret:
        fd=os.open(secret,os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);args+=['--unlock-secret-fd',str(fd)]
    if pair:
        for role in ['host','client']:
            fd=os.open(pair[role]['secret'],os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);args+=['--'+role+'-secret-fd',str(fd)]
    probes=[]
    if denyInputs:probes=[str(INPUTS/'request.json'),str(INPUTS/'primary-prepared.json'),str(INPUTS/(pair['name']+'-configuration.json')),str(INPUTS/(pair['name']+'-export.json'))]
    if denyModel:probes.append(str(BASE/'fixtures/model/profile.json'))
    native=[str(EXE),'durable-native-recovery',*args]
    wrapper=[str(BASE/'guest.py'),'worker',base64.b64encode(raw(dict(command=native,probes=probes,fds=fds))).decode()]
    cmd=['/usr/bin/sandbox-exec','-p',sandbox(denyInputs,denyModel,keychainDeny=False),'/usr/bin/python3',*wrapper]
    item=dict(label=label,command=native,sandbox=sandbox(denyInputs,denyModel,keychainDeny=False),joined=False,frames=[],certificates=[],exchanges=[])
    out=(BASE/'logs'/(label+'.stdout.log')).open('xb');err=(BASE/'logs'/(label+'.stderr.log')).open('xb')
    started=time.monotonic();p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,pass_fds=tuple(fds))
    for fd in fds:os.close(fd)
    item['pid']=p.pid;record['processes'].append(item);save();buf=b''
    try:
        while True:
            assert time.monotonic()-started<240,label+' timeout'
            if b'\n' not in buf:
                ready,_,_=select.select([p.stdout],[],[],1)
                if not ready:continue
                data=os.read(p.stdout.fileno(),4096)
                if not data:assert not buf;break
                out.write(data);out.flush();buf+=data
                assert out.tell()<=192<<20 and err.tell()<=192<<20 and len(buf.split(b'\n',1)[0])<=65536
                if b'\n' not in buf:continue
            line,buf=buf.split(b'\n',1);value=json.loads(line);assert raw(value)==line
            stage=value.get('stage')
            assert stage not in ['challenge','observe-witness'],'socket mode attempted pipe authority'
            if stage=='socket-authority':
                item['exchanges'].append(value)
                if value.get('certificate') and value['accepted']:item['certificates'].append(signed(value['certificate']))
            elif stage=='read-denial':assert value['paths']==probes;item['readDenials']=probes
            elif stage=='boundary':
                item['frames'].append(value);assert boundary in ['delay','loss']
                if boundary=='delay':time.sleep(11)
                else:item['joinedServiceLoss']=service_stop()
                p.stdin.write(raw(dict(stage='continue'))+b'\n');p.stdin.flush()
            else:
                item['frames'].append(value)
                if stage=='checkpoint':
                    assert checkpoint;p.kill();code=p.wait(timeout=10);assert code==-9;break
        code=p.wait(timeout=10);item.update(exitCode=code,joined=True,seconds=time.monotonic()-started)
        assert code==(-9 if checkpoint else expected),label+' exit '+str(code)
        if expected!=0:assert not [v for v in item['frames'] if v.get('stage') in ['complete','checkpoint']], 'stale output'
        return item
    finally:
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
        item.update(exitCode=p.returncode,joined=True,seconds=time.monotonic()-started)
        p.stdin.close();p.stdout.close();out.close();err.close();save()

def socket_probe():
    log=(BASE/'logs/probe-server.stderr.log').open('xb')
    cmd=['/usr/bin/sandbox-exec','-p',sandbox(),str(SERVICE),'probe-server','--endpoint',ENDPOINT]
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=log)
    item=dict(label='probe-server',pid=p.pid,command=cmd,joined=False);record['processes'].append(item);save()
    try:
        ready,_,_=select.select([p.stdout],[],[],10);assert ready
        assert json.loads(p.stdout.readline())['stage']=='probe-ready'
        client=json.loads(capture(['/usr/bin/sandbox-exec','-p',sandbox(),str(SERVICE),'probe-client','--endpoint',ENDPOINT]))
        assert client['bytes']==8192 and client.get('error') is None
        result=json.loads(p.stdout.readline());assert result['bytes']==8192
        assert p.wait(timeout=10)==0
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=10)
        item.update(exitCode=p.returncode,joined=True);p.stdout.close();log.close();save()
    Path(ENDPOINT).unlink()
    negative=json.loads(capture(['/usr/bin/sandbox-exec','-p',sandbox(),str(SERVICE),'network-probe','--endpoint',str(BASE/'other-socket/s'),'--keychains','/Users/threshold-auto/Library/Keychains']))
    assert all(negative[k] for k in ['otherUnixDenied','ipv4BindDenied','ipv6BindDenied','keychainReadDenied'])
    event('guest-literal-socket-feasibility',dict(allowed=client,denied=negative,sandbox=sandbox(),beforeOriginals=True,serviceSHA256=sha(SERVICE)))

def path(name):return BASE/'control'/(name+'.json')
def load(name):return json.loads(path(name).read_bytes())
def savepair(pair):write(path(pair['name']),pair)
def pairargs(pair):return ['--host-receipt',pair['host']['receipt'],'--host-digest',pair['host']['digest'],'--client-receipt',pair['client']['receipt'],'--client-digest',pair['client']['digest']]
def hashes(pair):
    result={}
    for role in ['host','client']:
        root=Path(pair[role]['root'])
        for p in sorted(root.rglob('*')):
            if p.is_file() and 'keys' not in p.relative_to(root).parts:
                assert not p.is_symlink();result[str(p.relative_to(BASE))]=sha(p)
        for p in (BASE/'control').glob(pair['name']+'-'+role+'.json*'):
            if p.is_file():result[str(p.relative_to(BASE))]=sha(p)
    return result

def fixture():
    write(BASE/'reports/keychains-before.json',metadata())
    request=json.loads((BASE/'fixtures/requests/ordinary.json').read_bytes());request['options']['maximumResponseTokens']=16
    write(INPUTS/'request.json',request)
    # Two real preparation passes freeze one exact binding before either run.
    for name in ['primary','reference']:
        command('prepare-'+name,['prepare-fixture','--model',BASE/'fixtures/model','--request',INPUTS/'request.json',
            '--operation','s107-original-common-operation','--output',INPUTS/(name+'-prepared.json'),'--public-model',INPUTS/(name+'-model.json')])
    assert (INPUTS/'primary-prepared.json').read_bytes()==(INPUTS/'reference-prepared.json').read_bytes()
    assert (INPUTS/'primary-model.json').read_bytes()==(INPUTS/'reference-model.json').read_bytes()
    e=json.loads((INPUTS/'primary-prepared.json').read_bytes());provider=json.loads(base64.b64decode(e['provider']))
    evidence=dict(preparedSHA256=sha(INPUTS/'primary-prepared.json'),provider=provider,requestSHA256=sha(INPUTS/'request.json'),
        publicModelSHA256=sha(INPUTS/'primary-model.json'),beforeEitherOriginal=True,
        compiler=compiler,compilerSHA256=sha(compiler),sdk=sdk,cmathSHA256=sha(Path(sdk)/'usr/include/c++/v1/cmath'),
        launcherSHA256=sha(shim),nativeCompileDisabled=False,modelSHA256={p.name:sha(p) for p in (BASE/'fixtures/model').iterdir()})
    write(BASE/'reports/fixture-binding.json',evidence);event('exact-common-preparation-frozen',evidence)
def original(name,service,subject):
    assert not list((BASE/'roots').iterdir())
    pair=dict(name=name,boot=boot(),subject=subject,descriptor=service['descriptor'],descriptorSHA256=service['descriptorSHA256'],servicePID=service['pid'])
    descriptor=json.loads(Path(pair['descriptor']).read_bytes())
    originals=next(x for x in descriptor['pairs'] if signed(x['host'])['subject']==subject)
    pair['originals']=originals;pair['registrations']={r:signed(originals[r]) for r in ['host','client']}
    configuration=INPUTS/(name+'-configuration.json');export=INPUTS/(name+'-export.json');savepair(pair)
    command(name+'-provision',['provision',*selectionargs(pair),'--witness-subject',subject,'--public-model',INPUTS/'primary-model.json','--request',INPUTS/'request.json',
        '--model',BASE/'fixtures/model','--prepared',INPUTS/'primary-prepared.json','--output',configuration])
    for role in ['host','client']:
        secret=BASE/'secrets'/(name+'-'+role);secret.write_text(os.urandom(32).hex());secret.chmod(0o600)
        pair[role]=dict(root=str(BASE/'roots'/(name+'-'+role)),receipt=str(BASE/'control'/(name+'-'+role+'.json')),secret=str(secret));savepair(pair)
        item=command(name+'-init-'+role,['init','--root',pair[role]['root'],'--role',role,'--configuration',configuration,'--owner-receipt',pair[role]['receipt']],secret=secret)
        pair[role]['digest']=item['frames'][0]['ownerReceiptDigest'];savepair(pair)
    admitted=command(name+'-admit',['admit',*pairargs(pair),*selectionargs(pair),'--export',export,'--request',INPUTS/'request.json'],secret=pair['host']['secret'])['frames'][0]
    accepted=command(name+'-accept',['accept',*pairargs(pair),*selectionargs(pair),'--export',export,'--original-issuer',admitted['issuer'],'--successful-export-digest',admitted['exportDigest']],secret=pair['client']['secret'])['frames'][0]
    assert accepted['admission']==admitted['admission'];pair['admission']=admitted;pair['initialHashes']=hashes(pair);savepair(pair)
    # Keep original encrypted records and public control; never actual Keychains.
    for relative in pair['initialHashes']:
        target=BASE/'originals'/name/relative;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(BASE/relative,target);target.chmod(0o600)
    event(name+'-original-admission',dict(boot=pair['boot'],admission=admitted,registrations=pair['registrations'],hashes=pair['initialHashes']))
    return pair
def run(pair,label,original=False,checkpoint=False,fault=None,boundary=None,expected=0,terminal=False):
    report=BASE/'reports'/(label+'-native.json')
    args=['run',*pairargs(pair),*selectionargs(pair),'--report',report]
    if original:args+=['--original']
    if checkpoint:args+=['--stop-after-calls','8','--leave-host-ahead']
    if fault:args+=['--fault',fault]
    item=command(label,args,pair=pair,checkpoint=checkpoint,boundary=boundary,expected=expected,denyInputs=not original,denyModel=terminal)
    if expected==0:
        data=json.loads(report.read_bytes());assert data['nativePeak']<=128<<20
        assert data['admission']==pair['admission']['admission']
        assert data['hostDeadline']==pair['registrations']['host']['deadline'] and data['clientDeadline']==pair['registrations']['client']['deadline']
        assert data['provider']==json.loads((BASE/'reports/fixture-binding.json').read_bytes())['provider']
        if checkpoint:
            assert data['nativeCalls']==8 and data['client']['high']>0 and not data['client']['terminal'] and data['hostHigh']>data['client']['high']
            pair['checkpoint']=data;pair['checkpointHashes']=hashes(pair);savepair(pair)
        return data,item
    assert not report.exists()
    return None,item

def retire(pair):
    current=boot()
    for role in ['host','client']:
        if role not in pair or not Path(pair[role]['root']).exists():continue
        assert pair[role].get('digest'),'original creator handback missing'
        args=['retire','--owner-receipt',pair[role]['receipt'],'--expected-receipt-digest',pair[role]['digest']]
        after=current!=pair['boot']
        if after:args+=['--after-boot']
        item=command((PHASE+'-' if PHASE.startswith('cleanup') else '')+pair['name']+'-retire-'+role,args,secret=pair[role]['secret'] if after else None)
        assert item['frames'][0]['stage']=='retired' and not Path(pair[role]['root']).exists()
    pair['retired']=True;savepair(pair)
    assert not list((BASE/'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
    event(pair['name']+'-original-key-retired',dict(rootAbsence=True,keychainAbsence=True,afterBoot=current!=pair['boot'],createdRoles=[r for r in ['host','client'] if pair.get(r,{}).get('digest')],unrelatedSentinel=sentinel_check()))
def keychain_metadata_probe():
    # Only existing nonsecret default/search metadata, as required by role init.
    source=BASE/'tmp/metadata-probe.c';binary=BASE/'tmp/metadata-probe'
    source.write_text(r'''#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>
#include <stdio.h>
int main(void) {
 SecKeychainRef key=0;OSStatus a=SecKeychainCopyDefault(&key);OSStatus b=-1,c=-1,d=-1;int exists=0;
 char path[4096]={0};UInt32 count=sizeof(path);SecKeychainStatus status=0;CFArrayRef list=0;
 if(a==0&&key){b=SecKeychainGetPath(key,&count,path);struct stat st;if(b==0)exists=lstat(path,&st)==0&&S_ISREG(st.st_mode);c=SecKeychainGetStatus(key,&status);}
 d=SecKeychainCopySearchList(&list);printf("{\"default\":%d,\"path\":%d,\"exists\":%d,\"status\":%d,\"search\":%d}\n",(int)a,(int)b,exists,(int)c,(int)d);
 if(key)CFRelease(key);if(list)CFRelease(list);return 0;
}
''')
    capture(['/usr/bin/sandbox-exec','-p',sandbox(),compiler,'-no-canonical-prefixes','-x','c',str(source),'-isysroot',sdk,'-framework','Security','-framework','CoreFoundation','-o',str(binary)])
    denied=json.loads(capture(['/usr/bin/sandbox-exec','-p',sandbox(),str(binary)]))
    native=json.loads(capture(['/usr/bin/sandbox-exec','-p',sandbox(keychainDeny=False),str(binary)]))
    assert native==dict(default=0,path=0,exists=1,status=0,search=0)
    event('native-keychain-metadata-feasibility',dict(deniedProfile=denied,nativeProfile=native,sourceSHA256=sha(source),binarySHA256=sha(binary),itemEnumeration=False,beforeOriginals=True))

def selected_pairs(caps):
    return [dict(subject=str(uuid.uuid4()),hostCap=int(h*1e9),clientCap=int(c*1e9)) for h,c in caps]

def exact_events(report):
    result=[];decoder=json.JSONDecoder()
    for batch in report['inbox']:
        text=base64.b64decode(batch['bytes']).decode();i=1;events=[]
        assert text.startswith('[') and text.endswith(']')
        while i<len(text)-1:
            _,end=decoder.raw_decode(text,i);events.append(text[i:end].encode());i=end
            if text[i:i+1]==',':i+=1
        result.extend(events[batch.get('skip',0):])
    return result

def live_replacement_probe(service,subject):
    cmd=['/usr/bin/sandbox-exec','-p',sandbox(),str(SERVICE),'receiver','--descriptor',service['descriptor'],'--digest',service['descriptorSHA256'],'--subject',subject]
    p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:out,err=p.communicate(raw(dict(op='exchange'))+b'\n',timeout=15)
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=10)
        record['processes'].append(dict(label='replacement-available',command=cmd,pid=p.pid,exitCode=p.returncode,joined=True));save()
    (BASE/'logs/replacement-available.stdout.log').write_bytes(out);(BASE/'logs/replacement-available.stderr.log').write_bytes(err)
    frames=[json.loads(line) for line in out.splitlines()]
    assert p.returncode==0 and frames[-1]['stage']=='eligible';return frames[-1]

def cleanup():
    for p in sorted((BASE/'control').glob('*.json')):
        pair=json.loads(p.read_bytes())
        if pair.get('name') and not pair.get('retired'):retire(pair)
    service_stop()
    assert not list((BASE/'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
    before=json.loads((BASE/'reports/keychains-before.json').read_bytes());after=metadata();assert before==after
    write(BASE/'reports/keychains-after.json',after)
    if (BASE/'secrets').exists():shutil.rmtree(BASE/'secrets')
    record['secretsAbsent']=True;record['retirementComplete']=True;record['unrelatedSentinel']=sentinel_check()

try:
    if not (BASE/'reports/keychains-before.json').exists():write(BASE/'reports/keychains-before.json',metadata())
    if PHASE.startswith('cleanup'):cleanup()
    elif PHASE=='retirement':
        socket_probe();keychain_metadata_probe();fixture()
        selected=selected_pairs([(90,150)]);svc=service_start('retirement',selected)
        pair=original('retirement',svc,selected[0]['subject']);retire(pair);service_stop();cleanup()
    else:
        socket_probe();keychain_metadata_probe();fixture()
        if PHASE!='loss':
            selected=selected_pairs([(600,900),(900,1200)])
            svc=service_start('positive',selected)
            started=time.monotonic();pair=original('primary',svc,selected[0]['subject'])
            cut,first=run(pair,'primary-cut',original=True,checkpoint=True)
            setupSeconds=time.monotonic()-started
            assert serviceOwner[0].poll() is None and boot()==pair['boot'] and hashes(pair)==pair['checkpointHashes']
            event('eight-call-checkpoint-and-joined-receiver',dict(report=cut,workerPID=first['pid'],exitCode=first['exitCode'],joined=first['joined'],setupSeconds=setupSeconds))
            result,second=run(pair,'primary-resumed');before=cut['inbox']
            assert second['pid']!=first['pid'] and result['nativeCalls']>0 and result['client']['terminal']
            assert result['inbox'][:len(before)]==before and result['beforeInbox']==before
            assert result['replayedBeforeNative']>=cut['hostHigh']-cut['client']['high']
            assert all(result[x]==0 for x in ['modelPrepares','requestPreparations','templateCalls','requestTokenizations','issues','begins'])
            assert result['modelLoads']==1 and result['traces'][0]['offsets'][0]>0
            a=first['exchanges'][0];b=second['exchanges'][0]
            ca=json.loads(base64.b64decode(a['request']));cb=json.loads(base64.b64decode(b['request']))
            assert ca['receiverBoot']==cb['receiverBoot'] and ca['receiverIncarnation']!=cb['receiverIncarnation'] and ca['nonce']!=cb['nonce']
            assert a['sent']!=b['sent'] and serviceOwner[0].pid==pair['servicePID'] and serviceOwner[0].poll() is None
            assert ca['witness']==cb['witness']==pair['originals']['pin']
            pair['terminal']=result;savepair(pair)
            event('same-service-fresh-receiver-native-continuation',dict(report=result,firstReceiver=first['pid'],freshReceiver=second['pid'],originalService=svc,firstChallenge=ca,freshChallenge=cb,sameBoot=True,noReboot=True))
            replay,third=run(pair,'primary-terminal-replay',terminal=True)
            assert replay['inbox']==result['inbox'] and replay['client']==result['client']
            assert all(replay[x]==0 for x in ['nativeCalls','modelLoads','modelPrepares','requestPreparations','templateCalls','requestTokenizations','issues','begins']) and not replay['traces']
            event('model-free-terminal-replay-under-read-denial',dict(report=replay,denied=third['readDenials']))
            retire(pair)
            reference=original('reference',svc,selected[1]['subject']);ref,_=run(reference,'reference-uninterrupted',original=True)
            assert ref['provider']==result['provider'] and ref['client']['terminal'] and exact_events(ref)==exact_events(result)
            event('exact-independent-reference',dict(exactEventBytes=True,eventCount=len(exact_events(ref)),eventStreamSHA256=hashlib.sha256(b''.join(exact_events(ref))).hexdigest(),report=ref))
            retire(reference);positiveJoin=service_stop()
            # Each serial negative gets fresh originals. Budget follows measured setup.
            short=max(45,int(setupSeconds*2+20));assert short<=120
            event('negative-headroom-selected-before-originals',dict(measuredSetupSeconds=setupSeconds,shortSeconds=short,longSeconds=short+180))
            for role in ['host','client']:
                name=role+'-expiry';other='client' if role=='host' else 'host'
                selected=selected_pairs([(short,short+180) if role=='host' else (short+180,short)])
                svc=service_start(name,selected);pair=original(name,svc,selected[0]['subject'])
                active,_=run(pair,name+'-cut',original=True,checkpoint=True)
                limit=pair['registrations'][role]['deadline'];last=active['evaluation']['witness']['nanoseconds']
                remaining=max(0,(limit-last)/1e9+1);event(name+'-wait',dict(seconds=remaining,eligibleCheckpoint=active['evaluation'],nativeCalls=active['nativeCalls']))
                end=time.monotonic()+remaining;tick=0
                while time.monotonic()<end:
                    time.sleep(min(20,max(0,end-time.monotonic())));tick+=1
                    assert controller(dict(kind='heartbeat',label=name,remainingSeconds=max(0,end-time.monotonic())))=={'kind':'ack'}
                _,refusal=run(pair,name+'-refusal',expected=1)
                sample=refusal['certificates'][0]['sample']['nanoseconds']
                assert limit<=sample<pair['registrations'][other]['deadline']
                assert refusal['frames'][-1]['stage']=='native-refusal' and refusal['frames'][-1]['nativeCalls']==0
                event(name+'-active-independent-refusal',dict(witnessSample=sample,expiredDeadline=limit,otherDeadline=pair['registrations'][other]['deadline'],refusal=refusal['frames'][-1]))
                retire(pair);service_stop()
        selected=selected_pairs([(300,450)]);svc=service_start('faults',selected);pair=original('faults',svc,selected[0]['subject'])
        run(pair,'faults-cut',original=True,checkpoint=True)
        if PHASE!='loss':
            _,delayed=run(pair,'after-native-delay',fault='after-native',boundary='delay',expected=1)
            assert delayed['seconds']>=11 and delayed['frames'][-1]['nativeCalls']==1
            assert all(x['accepted'] for x in delayed['exchanges'])
            event('completed-action-native-commit-age-refusal',dict(seconds=delayed['seconds'],refusal=delayed['frames'][-1],completedExchanges=len(delayed['exchanges']),diskState='requires-authenticated-reconciliation'))
        _,lost=run(pair,'actual-socket-loss',fault='before-native',boundary='loss',expected=1)
        assert lost['joinedServiceLoss']['joined'] and not lost['exchanges'][-1]['accepted']
        assert lost['frames'][-1]['stage']=='native-refusal'
        event('actual-socket-loss-at-next-exchange',dict(joinedOriginal=lost['joinedServiceLoss'],refusal=lost['frames'][-1],failedExchange=lost['exchanges'][-1],observationLimit='completed action remains bounded until next exchange; no continuous observation'))
        replacementSelection=selected_pairs([(300,450)]);replacement=service_start('replacement',replacementSelection)
        assert replacement['identity']!=pair['originals']['pin'];available=live_replacement_probe(replacement,replacementSelection[0]['subject'])
        before=hashes(pair);_,rejected=run(pair,'replacement-refusal',expected=1,terminal=True)
        assert hashes(pair)==before and not rejected['exchanges'][-1]['accepted']
        assert rejected['frames'][-1]['nativeCalls']==rejected['frames'][-1]['modelLoads']==0
        event('available-replacement-refuses-original-selection',dict(originalPin=pair['originals']['pin'],replacementPin=replacement['identity'],replacementEligible=available,refusal=rejected['frames'][-1],unchangedSelectedBytes=True,denied=rejected['readDenials']))
        retire(pair);service_stop();cleanup()
    record['result']='PASS'
except BaseException as error:
    record.update(result='FAIL',failure=str(error),traceback=traceback.format_exc())
    try:cleanup()
    except BaseException as cleanupError:record['cleanupFailure']=str(cleanupError);record['cleanupTraceback']=traceback.format_exc()
finally:
    service_stop()
    record['rootObservations']=[str(p.relative_to(BASE)) for p in (BASE/'roots').iterdir()]
    record['keychainPaths']=[str(p.relative_to(BASE)) for p in BASE.rglob('*.keychain-db')]
    record['knownWorkersJoined']=all(p['joined'] for p in record['processes']);save()
    controller(dict(kind='phase-result',evidence={k:v for k,v in record.items() if k!='processes'}))
sys.exit(0 if record['result']=='PASS' else 1)
