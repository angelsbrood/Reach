#!/usr/bin/env python3
"""Serial S101 actual native campaign. UID503 originals and keys stay in this guest."""
import base64, hashlib, json, os, select, shutil, stat, subprocess, sys, time, traceback, uuid
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(sys.argv[1]).resolve(strict=True); PHASE=sys.argv[2]
assert str(BASE).startswith('/Users/threshold-auto/reach-s101-') and os.getuid()==503
assert BASE.stat().st_uid==503 and stat.S_IMODE(BASE.stat().st_mode)==0o700
os.umask(0o077)
for name in ['logs','reports','roots','control','secrets','originals','tmp','original-inputs']:
    (BASE/name).mkdir(exist_ok=True,mode=0o700)
EXE=BASE/'bin/reachd'; INPUTS=BASE/'original-inputs'
record=dict(phase=PHASE,wrapperPID=os.getpid(),processes=[],result='RUNNING')
def raw(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def write(p,x):p.write_bytes(raw(x)+b'\n');p.chmod(0o600)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save():write(BASE/'reports'/(PHASE+'.json'),record)
def controller(value):
    denied = PHASE in ['resume-primary','terminal-primary','retire-primary','replacement-refusal'] or PHASE.startswith('cleanup')
    excluded = [INPUTS,BASE/'fixtures/requests'] if denied else []
    if PHASE in ['terminal-primary','replacement-refusal'] or PHASE.startswith('cleanup'):excluded.append(BASE/'fixtures/model')
    metrics=BASE/'reports/allocation.json'
    old=json.loads(metrics.read_bytes()) if metrics.exists() else {}
    def allocation(root):
        total=root.lstat().st_blocks*512
        for directory,dirs,files in os.walk(root):
            for name in list(dirs):
                p=Path(directory)/name
                if p in excluded:total+=old[str(p)];dirs.remove(name)
                else:total+=p.lstat().st_blocks*512
            for name in files:total+=(Path(directory)/name).lstat().st_blocks*512
        return total
    if not denied:
        old={str(p):allocation(p) for p in [INPUTS,BASE/'fixtures/requests',BASE/'fixtures/model']}
        write(metrics,old)
    owned=allocation(BASE);fixture=allocation(BASE/'fixtures')
    free=shutil.disk_usage(BASE).free;assert owned<=32<<30 and fixture<=3<<30 and free>=30<<30
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
    assert p.returncode==0;return out
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

def command(label,args,secret=None,pair=None,initial=None,expected=0,checkpoint=False,boundary=None,loss=False):
    fds=[];args=list(map(str,args))
    if secret:
        fd=os.open(secret,os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);args+=['--unlock-secret-fd',str(fd)]
    if pair:
        for role in ['host','client']:
            fd=os.open(pair[role]['secret'],os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);args+=['--'+role+'-secret-fd',str(fd)]
    cmd=[str(EXE),'durable-native-recovery',*args]
    item=dict(label=label,command=cmd,joined=False,frames=[],certificates=[],networkDenied=True)
    out=(BASE/'logs'/(label+'.stdout.log')).open('xb');err=(BASE/'logs'/(label+'.stderr.log')).open('xb')
    started=time.monotonic();p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,pass_fds=tuple(fds))
    for fd in fds:os.close(fd)
    item['pid']=p.pid;record['processes'].append(item);save();buf=b''
    try:
        if initial is not None:p.stdin.write(initial+b'\n');p.stdin.flush()
        while True:
            assert time.monotonic()-started<240,label+' timeout'
            if b'\n' not in buf:
                ready,_,_=select.select([p.stdout],[],[],1)
                if not ready:continue
                data=os.read(p.stdout.fileno(),4096)
                if not data:assert not buf;break
                out.write(data);out.flush();buf+=data
                assert out.tell()<=192<<20 and len(buf.split(b'\n',1)[0])<=65536
                if b'\n' not in buf:continue
            line,buf=buf.split(b'\n',1);value=json.loads(line);assert raw(value)==line
            stage=value.get('stage')
            if stage in ['challenge','observe-witness']:
                if stage=='observe-witness' and loss:
                    assert controller(dict(kind='stop-witness'))=={'kind':'ack'};reply=dict(stage='witness-observation',lost=True)
                else:reply=controller(dict(kind='witness',request=value))
                if reply.get('certificate'):item['certificates'].append(signed(reply['certificate']))
                p.stdin.write(raw(reply)+b'\n');p.stdin.flush()
            elif stage=='boundary':
                item['frames'].append(value);assert boundary in ['delay','loss']
                if boundary=='delay':time.sleep(11)
                p.stdin.write(raw(dict(stage='observe' if boundary=='loss' else 'continue'))+b'\n');p.stdin.flush()
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
            '--operation','s101-original-common-operation','--output',INPUTS/(name+'-prepared.json'),'--public-model',INPUTS/(name+'-model.json')])
    assert (INPUTS/'primary-prepared.json').read_bytes()==(INPUTS/'reference-prepared.json').read_bytes()
    assert (INPUTS/'primary-model.json').read_bytes()==(INPUTS/'reference-model.json').read_bytes()
    e=json.loads((INPUTS/'primary-prepared.json').read_bytes());provider=json.loads(base64.b64decode(e['provider']))
    evidence=dict(preparedSHA256=sha(INPUTS/'primary-prepared.json'),provider=provider,requestSHA256=sha(INPUTS/'request.json'),
        publicModelSHA256=sha(INPUTS/'primary-model.json'),beforeEitherOriginal=True,
        compiler=compiler,compilerSHA256=sha(compiler),sdk=sdk,cmathSHA256=sha(Path(sdk)/'usr/include/c++/v1/cmath'),
        launcherSHA256=sha(shim),nativeCompileDisabled=False,modelSHA256={p.name:sha(p) for p in (BASE/'fixtures/model').iterdir()})
    write(BASE/'reports/fixture-binding.json',evidence);event('exact-common-preparation-frozen',evidence)
def original(name,caps):
    assert not list((BASE/'roots').iterdir())
    pair=dict(name=name,boot=boot(),subject=str(uuid.uuid4()))
    response=controller(dict(kind='witness',request=dict(stage='register',subject=pair['subject'],hostSeconds=caps[0],clientSeconds=caps[1])))
    originals=base64.b64decode(response['originals']);decoded=json.loads(originals)
    pair['originals']=decoded;pair['registrations']={r:signed(decoded[r]) for r in ['host','client']}
    configuration=INPUTS/(name+'-configuration.json');export=INPUTS/(name+'-export.json');savepair(pair)
    command(name+'-provision',['provision','--public-model',INPUTS/'primary-model.json','--request',INPUTS/'request.json',
        '--model',BASE/'fixtures/model','--prepared',INPUTS/'primary-prepared.json','--output',configuration],initial=originals)
    for role in ['host','client']:
        secret=BASE/'secrets'/(name+'-'+role);secret.write_text(os.urandom(32).hex());secret.chmod(0o600)
        pair[role]=dict(root=str(BASE/'roots'/(name+'-'+role)),receipt=str(BASE/'control'/(name+'-'+role+'.json')),secret=str(secret));savepair(pair)
        item=command(name+'-init-'+role,['init','--root',pair[role]['root'],'--role',role,'--configuration',configuration,'--owner-receipt',pair[role]['receipt']],secret=secret)
        pair[role]['digest']=item['frames'][0]['ownerReceiptDigest'];savepair(pair)
    admitted=command(name+'-admit',['admit',*pairargs(pair),'--export',export,'--request',INPUTS/'request.json'],secret=pair['host']['secret'])['frames'][0]
    accepted=command(name+'-accept',['accept',*pairargs(pair),'--export',export,'--original-issuer',admitted['issuer'],'--successful-export-digest',admitted['exportDigest']],secret=pair['client']['secret'])['frames'][0]
    assert accepted['admission']==admitted['admission'];pair['admission']=admitted;pair['initialHashes']=hashes(pair);savepair(pair)
    # Keep original encrypted records and public control; never actual Keychains.
    for relative in pair['initialHashes']:
        target=BASE/'originals'/name/relative;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(BASE/relative,target);target.chmod(0o600)
    event(name+'-original-admission',dict(boot=pair['boot'],admission=admitted,registrations=pair['registrations'],hashes=pair['initialHashes']))
    return pair
def run(pair,label,original=False,checkpoint=False,fault=None,boundary=None,loss=False,expected=0):
    report=BASE/'reports'/(label+'-native.json')
    args=['run',*pairargs(pair),'--report',report]
    if original:args+=['--original']
    if checkpoint:args+=['--stop-after-calls','8','--leave-host-ahead']
    if fault:args+=['--fault',fault]
    item=command(label,args,pair=pair,checkpoint=checkpoint,boundary=boundary,loss=loss,expected=expected)
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
        item=command(PHASE+'-retire-'+role,args,secret=pair[role]['secret'] if after else None)
        assert item['frames'][0]['stage']=='retired' and not Path(pair[role]['root']).exists()
    pair['retired']=True;savepair(pair)
    assert not list((BASE/'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
    event(pair['name']+'-original-key-retired-'+PHASE,dict(rootAbsence=True,keychainAbsence=True,afterBoot=current!=pair['boot']))
try:
    if PHASE in ['resume-primary','terminal-primary','replacement-refusal']:
        refused=[]
        probes=[INPUTS/'request.json',INPUTS/'primary-prepared.json',INPUTS/'primary-configuration.json',INPUTS/'primary-export.json']
        if PHASE=='replacement-refusal':probes=[INPUTS/'request.json',INPUTS/'primary-prepared.json',INPUTS/'faults-configuration.json',INPUTS/'faults-export.json']
        if PHASE in ['terminal-primary','replacement-refusal']:probes.append(BASE/'fixtures/model/profile.json')
        for probe in probes:
            try:
                fd=os.open(probe,os.O_RDONLY|os.O_NOFOLLOW);os.close(fd)
            except PermissionError:refused.append(str(probe.relative_to(BASE)))
            else:raise AssertionError('selected read denial did not apply')
        event(PHASE+'-read-denial-probes',dict(refused=refused,noContentsRead=True))
    if PHASE=='fixture':fixture()
    elif PHASE=='original-primary':
        pair=original('primary',(600,900));data,item=run(pair,'primary-cut',original=True,checkpoint=True)
        event('actual-eight-call-checkpoint',dict(report=data,workerPID=item['pid'],exitCode=item['exitCode'],joined=item['joined']))
    elif PHASE=='resume-primary':
        pair=load('primary');assert boot()!=pair['boot'] and hashes(pair)==pair['checkpointHashes']
        result,item=run(pair,'primary-resumed');before=pair['checkpoint']['inbox']
        assert result['nativeCalls']>0 and result['client']['terminal'] and result['inbox'][:len(before)]==before
        assert result['beforeInbox']==before and result['replayedBeforeNative']>=pair['checkpoint']['hostHigh']-pair['checkpoint']['client']['high']
        assert all(result[x]==0 for x in ['modelPrepares','requestPreparations','templateCalls','requestTokenizations','issues','begins'])
        assert result['modelLoads']==1 and result['traces'][0]['offsets'][0]>0
        pair['terminal']=result;savepair(pair);event('actual-postboot-native-continuation',result)
    elif PHASE=='terminal-primary':
        pair=load('primary');result,item=run(pair,'primary-terminal-replay')
        assert result['inbox']==pair['terminal']['inbox'] and result['client']==pair['terminal']['client']
        assert result['nativeCalls']==result['modelLoads']==0 and not result['traces']
        event('terminal-replay-artifact-reads-denied',result)
    elif PHASE=='retire-primary':retire(load('primary'))
    elif PHASE=='reference':
        pair=original('reference',(600,900));result,item=run(pair,'reference-uninterrupted',original=True)
        primary=load('primary')['terminal'];assert result['provider']==primary['provider'] and result['client']['terminal']
        assert [x['bytes'] for x in result['inbox']]==[x['bytes'] for x in primary['inbox']]
        assert result['originalBoot']==result['receiverBoot']
        event('exact-independent-reference',dict(exactNativeEventBytes=True,primaryAdmission=primary['admission'],referenceAdmission=result['admission'],report=result))
        retire(pair)
    elif PHASE in ['host-expiry','client-expiry']:
        role='host' if PHASE=='host-expiry' else 'client';other='client' if role=='host' else 'host'
        pair=original(PHASE,(45,180) if role=='host' else (180,45));data,_=run(pair,PHASE+'-cut',original=True,checkpoint=True)
        limit=pair['registrations'][role]['deadline'];last=data['evaluation']['witness']['nanoseconds']
        remaining=max(0,(limit-last)/1e9+1);event(PHASE+'-wait',dict(seconds=remaining,activeCheckpoint=data['hostHigh']))
        time.sleep(remaining)
        _,item=run(pair,PHASE+'-refusal',expected=1)
        sample=item['certificates'][0]['sample']['nanoseconds'];assert limit<=sample<pair['registrations'][other]['deadline']
        assert item['frames'][-1]['stage']=='native-refusal' and item['frames'][-1]['nativeCalls']==0
        event(PHASE+'-independent-active-refusal',dict(witnessSample=sample,expiredDeadline=limit,otherDeadline=pair['registrations'][other]['deadline'],nativeCalls=0,activeOriginalCheckpoint=True))
        retire(pair)
    elif PHASE=='faults':
        pair=original('faults',(180,240));run(pair,'faults-cut',original=True,checkpoint=True)
        for point in ['after-native','after-commit']:
            _,item=run(pair,point+'-delay',fault=point,boundary='delay',expected=1)
            assert item['seconds']>=11 and item['frames'][-1]['nativeCalls']==1
            event(point+'-eleven-second-refusal',dict(nativeCalls=1,noPublication=True,seconds=item['seconds'],diskState='requires-authenticated-reconciliation'))
        _,item=run(pair,'observed-loss',fault='before-native',boundary='loss',loss=True,expected=1)
        assert item['frames'][-1]['nativeCalls']==0
        event('observed-witness-loss-refused',dict(originalWitness=pair['originals']['pin'],nativeCalls=0,workerPID=item['pid'],joined=item['joined']))
    elif PHASE=='replacement-refusal':
        pair=load('faults');before=hashes(pair)
        replacement=controller(dict(kind='replacement-witness'));assert replacement['identity']!=pair['originals']['pin']
        _,item=run(pair,'replacement-refusal',expected=1)
        # An initial authority failure precedes the runtime's native-counter
        # reporting region. Keep that observation distinct from a counter frame.
        frames=[json.loads(line) for line in (BASE/'logs/replacement-refusal.stdout.log').read_bytes().splitlines()]
        assert len(frames)==1 and frames[0]['stage']=='challenge'
        challenge=json.loads(base64.b64decode(frames[0]['challenge']))
        assert challenge['witness']==pair['originals']['pin']
        assert challenge['registrations']==[hashlib.sha256(base64.b64decode(pair['originals'][r])).hexdigest() for r in ['host','client']]
        assert not item['frames'] and not item['certificates']
        assert (BASE/'logs/replacement-refusal.stderr.log').read_text()=='durable-native-recovery refused (AuthorityError:ineligible).\n'
        assert hashes(pair)==before
        event('replacement-initial-authority-refused',dict(originalWitness=pair['originals']['pin'],replacement=replacement['identity'],
            originalChallenge=challenge,workerPID=item['pid'],joined=item['joined'],modelReadsDenied=True,originalSelectedBytesUnchanged=True,
            noPublication=True,counterFramePresent=False,nativeCalls=0,
            zeroNativeBasis='Rejected initial challenge before native factory and key transaction in the bound runtime; model reads denied.'))
        retire(pair)
    elif PHASE.startswith('cleanup'):
        for p in sorted((BASE/'control').glob('*.json')):
            pair=json.loads(p.read_bytes())
            if pair.get('name') and not pair.get('retired'):retire(pair)
        assert not list((BASE/'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
        before=json.loads((BASE/'reports/keychains-before.json').read_bytes());after=metadata();assert before==after
        write(BASE/'reports/keychains-after.json',after);shutil.rmtree(BASE/'secrets');record['secretsAbsent']=True
    else:raise ValueError('unselected phase')
    record['result']='PASS'
except BaseException as error:record.update(result='FAIL',failure=str(error),traceback=traceback.format_exc())
finally:
    record['rootObservations']=[str(p.relative_to(BASE)) for p in (BASE/'roots').iterdir()]
    record['keychainPaths']=[str(p.relative_to(BASE)) for p in BASE.rglob('*.keychain-db')]
    record['knownWorkersJoined']=all(p['joined'] for p in record['processes']);save()
    controller(dict(kind='phase-result',evidence={k:v for k,v in record.items() if k!='processes'}))
sys.exit(0 if record['result']=='PASS' else 1)
