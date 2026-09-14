#!/usr/bin/env python3
"""Serial S105 actual native campaign. UID503 originals and keys stay in this guest."""
import base64, hashlib, json, os, select, shutil, stat, subprocess, sys, time, traceback, uuid
from pathlib import Path
from budget import protocol_budget
sys.dont_write_bytecode=True
BASE=Path(sys.argv[1]).resolve(strict=True); PHASE=sys.argv[2]
LANE,ACTION=PHASE.split('-',1) if PHASE.startswith(('normal-','fixture-')) else (None,PHASE)
DENIED=ACTION in ['resume-probe','resume-guided','ready-primary','terminal-primary','duplicate-primary','retire-primary'] or ACTION.startswith('cleanup')
MODEL_DENIED=ACTION in ['terminal-primary','duplicate-primary'] or ACTION.startswith('cleanup')
assert str(BASE).startswith('/Users/threshold-auto/reach-s105-') and os.getuid()==503
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
    denied = DENIED
    excluded = [INPUTS,BASE/'fixtures/requests'] if denied else []
    if MODEL_DENIED:excluded.extend([BASE/'fixtures/model',BASE/'fixtures/state-model'])
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
        old={str(p):allocation(p) for p in [INPUTS,BASE/'fixtures/requests',BASE/'fixtures/model',BASE/'fixtures/state-model']}
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

def command(label,args,secret=None,pair=None,initial=None,expected=0,checkpoint=False,boundary=None,loss=False,lane=None):
    fds=[];args=list(map(str,args))
    if secret:
        fd=os.open(secret,os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);args+=['--unlock-secret-fd',str(fd)]
    if pair:
        for role in ['host','client']:
            fd=os.open(pair[role]['secret'],os.O_RDONLY|os.O_NOFOLLOW);fds.append(fd);args+=['--'+role+'-secret-fd',str(fd)]
    selected=lane or LANE;assert selected in ['normal','fixture']
    cmd=[str(executable(selected)),*(['durable-native-recovery'] if selected=='normal' else []),*args]
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

def original(name,caps):
    assert not list((BASE/'roots').iterdir())
    pair=dict(name=name,boot=boot(),subject=str(uuid.uuid4()))
    response=controller(dict(kind='witness',request=dict(stage='register',subject=pair['subject'],hostSeconds=caps[0],clientSeconds=caps[1])))
    originals=base64.b64decode(response['originals']);decoded=json.loads(originals)
    pair['originals']=decoded;pair['registrations']={r:signed(decoded[r]) for r in ['host','client']}
    configuration=INPUTS/(name+'-configuration.json');export=INPUTS/(name+'-export.json');savepair(pair)
    command(name+'-provision',['provision','--public-model',INPUTS/(LANE+'-primary-model.json'),'--request',INPUTS/'request.json',
        '--model',model(LANE),'--prepared',INPUTS/(LANE+'-primary-prepared.json'),'--output',configuration],initial=originals)
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
def retire(pair):
    current=boot()
    for role in ['host','client']:
        if role not in pair or not Path(pair[role]['root']).exists():continue
        assert pair[role].get('digest'),'original creator handback missing'
        args=['retire','--owner-receipt',pair[role]['receipt'],'--expected-receipt-digest',pair[role]['digest']]
        after=current!=pair['boot']
        if after:args+=['--after-boot']
        item=command(PHASE+'-retire-'+pair['name']+'-'+role,args,secret=pair[role]['secret'] if after else None,lane=pair['name'].split('-',1)[0])
        assert item['frames'][0]['stage']=='retired' and not Path(pair[role]['root']).exists()
    pair['retired']=True;savepair(pair)
    assert not list((BASE/'roots').iterdir()) and not list(BASE.rglob('*.keychain-db'))
    event(pair['name']+'-original-key-retired-'+PHASE,dict(rootAbsence=True,keychainAbsence=True,afterBoot=current!=pair['boot']))
def model(lane):return BASE/'fixtures'/('model' if lane=='normal' else 'state-model')
def executable(lane):return BASE/'bin'/('reachd' if lane=='normal' else 'reach-allowed-recovery-fixture')
def bind(lane):return json.loads((BASE/'reports/fixture-binding.json').read_bytes())[lane]
def allsteps(report,directory,key):
    result=[]
    for reference in report[key]:
        p=directory/reference['file'];data=p.read_bytes()
        assert p.parent==directory and len(data)==reference['bytes'] and sha(p)==reference['sha256'] and len(data)<=65536
        item=json.loads(data);assert raw(item)==data;result.append(item)
    return result
def feasibility():
    write(BASE/'reports/keychains-before.json',metadata())
    request=json.loads((BASE/'fixtures/requests/native-schema-tool.json').read_bytes())
    assert request['options']['maximumResponseTokens']==64 and request['options']['toolCalling']=='allowed'
    assert len(request['tools'])==1 and request.get('schema') and request['context']['includeSchemaInPrompt']==False;write(INPUTS/'request.json',request)
    bindings={}
    for lane in ['normal','fixture']:
        for who in ['primary','reference']:
            command(lane+'-prepare-'+who,['prepare-fixture','--model',model(lane),'--request',INPUTS/'request.json',
                '--operation','s105-original-common-operation','--output',INPUTS/(lane+'-'+who+'-prepared.json'),
                '--public-model',INPUTS/(lane+'-'+who+'-model.json')],lane=lane)
        assert (INPUTS/(lane+'-primary-prepared.json')).read_bytes()==(INPUTS/(lane+'-reference-prepared.json')).read_bytes()
        assert (INPUTS/(lane+'-primary-model.json')).read_bytes()==(INPUTS/(lane+'-reference-model.json')).read_bytes()
        report=BASE/'reports'/(lane+'-feasibility.json')
        probe=command(lane+'-feasibility',['probe-allowed-fixture','--model',model(lane),'--prepared',INPUTS/(lane+'-primary-prepared.json'),'--report',report],lane=lane)['frames'][0]
        assert probe['stage']=='allowed-feasibility' and probe['beforeOriginals'] and probe['successful']
        assert probe['readyRestoreCalls']==probe['readyDeliveryCalls']==probe['originalRequestEncodes']==0
        assert probe['providerBytes']<=16384 and probe['maximumStepFrameBytes']<=65536
        assert probe['nativePeak']<=128<<20 and probe['maximumActionNanoseconds']<10_000_000_000
        rows=[x for x in allsteps(probe,Path(str(report)+'.steps'),'steps') if x['operation']!='ready-restore']
        assert rows[0]['operation']=='prepare' and rows[-1]['operation']=='ready-deliver'
        budget=protocol_budget(probe,rows,lane)
        assert probe['ready']['route']==('schema' if lane=='normal' else 'calls') and probe['ready']['proseDelivered']==0
        if lane=='normal':assert probe['ready']['inputTokens']==2*probe['ready']['probe']['promptTokens']
        else:assert len(probe['ready']['proposals'])==len(probe['ready']['completedCalls'])==1
        e=json.loads((INPUTS/(lane+'-primary-prepared.json')).read_bytes());providerBytes=base64.b64decode(e['provider'])
        bindings[lane]=dict(provider=json.loads(providerBytes),preparedSHA256=sha(INPUTS/(lane+'-primary-prepared.json')),
            publicModelSHA256=sha(INPUTS/(lane+'-primary-model.json')),protocolBudget=budget,
            modelSHA256={p.name:sha(p) for p in model(lane).iterdir()},executableSHA256=sha(executable(lane)),
            beforeEitherOriginal=True,nativeCalls=probe['nativeCalls'],nativePeak=probe['nativePeak'],maximumFrameBytes=probe['maximumStepFrameBytes'])
    command('normal-rejects-fixture',['prepare-fixture','--model',model('fixture'),'--request',INPUTS/'request.json',
        '--operation','s105-original-common-operation','--output',INPUTS/'forbidden-prepared.json','--public-model',INPUTS/'forbidden-model.json'],lane='normal',expected=1)
    assert not (INPUTS/'forbidden-prepared.json').exists() and not (INPUTS/'forbidden-model.json').exists()
    bindings['common']=dict(requestSHA256=sha(INPUTS/'request.json'),metallibSHA256=sha(BASE/'bin/mlx.metallib'),
        normalFixtureRejection=True,compilerSHA256=sha(compiler),launcherSHA256=sha(shim),sdk=sdk,nativeCompileDisabled=False)
    write(BASE/'reports/fixture-binding.json',bindings);event('exact-common-preparation-frozen',bindings)

def steps(report,label):
    result=allsteps(report,BASE/'reports'/(label+'-native.json.steps'),'allowedSteps')
    groups={}
    for item in result:
        assert item['actionNanoseconds']<10_000_000_000
        maximum=2 if item['operation'] in ['prepare','next-pass'] else 0 if item['operation'] in ['restore','ready-deliver'] else 1
        assert item['nativeCalls']<=maximum
        groups.setdefault(item['action'],[]).append(item)
    for group in groups.values():
        assert len(group)<=2 and sum(x['nativeCalls'] for x in group)<=2
        if len(group)==2:assert all(x['operation']=='advance' for x in group)
    return result
def run(pair,label,original=False,allowed='none',fault=None,boundary=None,expected=0,duplicate=False):
    report=BASE/'reports'/(label+'-native.json');args=['run',*pairargs(pair),'--report',report]
    if original:args+=['--original']
    if allowed!='none':
        args+=['--allowed-boundary',allowed]
        # Both probes remain private. Schema guidance retains a host-ahead
        # fragment beyond an already visible nonterminal client prefix.
        args+=['--leave-host-ahead']
    if duplicate:args+=['--duplicate-exact']
    if fault:args+=['--fault',fault]
    item=command(label,args,pair=pair,checkpoint=allowed in ['probe','route-ready','guided','ready'],boundary=boundary,expected=expected)
    if expected!=0:
        assert not report.exists();return None,item
    data=json.loads(report.read_bytes());assert data['nativePeak']<=128<<20 and len(raw(data))<=65536
    assert data['admission']==pair['admission']['admission'] and data['provider']==bind(LANE)['provider']
    assert data['hostDeadline']==pair['registrations']['host']['deadline'] and data['clientDeadline']==pair['registrations']['client']['deadline']
    assert data['actions']==len(item['certificates'])<=62
    observed=steps(data,label)
    if data.get('allowedProgress'):
        assert observed[0]['progress']==data['allowedInitial'] and observed[-1]['progress']==data['allowedProgress']
        assert observed[-1]['progress']['coordinator'] # Authenticated selected coordinator/child diagnostics.
    if allowed=='probe':
        progress=data['allowedProgress'];assert progress['phase']=='probe' and progress['probe']['rawTokens']>0 and progress['proseDelivered']==0
        assert data['nativeCalls']>0 and data['client']['registrations']==0
        assert data['client']['high']==data['hostHigh']==0 and not data['inbox']
        pair['checkpoint']=data;pair['checkpointHashes']=hashes(pair);savepair(pair)
    if allowed=='guided':
        progress=data['allowedProgress'];g=progress['guided']
        assert progress['phase']=='guided' and g['consumedTokens']>0 and g['pendingTokens']>0 and base64.b64decode(progress['whole'])
        assert all(x['origin']=='forced' for x in g['accepts'][g['consumedTokens']:])
        assert progress['proseDelivered']==0 and data['client']['registrations']==0 and not data['client']['terminal']
        if LANE=='normal':
            assert progress['route']=='schema' and data['hostHigh']>data['client']['high']>0
            assert any('responseAppend' in event for batch in data['inbox'] for event in json.loads(base64.b64decode(batch['bytes'])))
        else:assert progress['route']=='calls' and data['hostHigh']==data['client']['high']==0
        pair['guidedCheckpoint']=data;pair['checkpointHashes']=hashes(pair);pair['guidedBoot']=boot();savepair(pair)
    if allowed=='ready':
        progress=data['allowedProgress'];assert progress['phase']=='finalReady' and progress['outcome']=='complete'
        assert data['client']['registrations']==0 and not data['client']['terminal']
        assert data['hostHigh']-data['client']['high'] in ([0,1] if LANE=='normal' else [0])
        assert progress['guided']['interceptedEndings']==1 and len(progress['completed'])==1
        assert len(progress['completedCalls'])==(1 if LANE=='fixture' else 0)
        assert progress['completed'][0]['kind']==('tool' if LANE=='fixture' else 'schema')
    return data,item

def resumed(pair,label,boundary,saved):
    result,item=run(pair,label,allowed=boundary)
    assert result['allowedInitial']==saved['allowedProgress'] and result['nativeCalls']>0
    assert all(result[x]==0 for x in ['requestPreparations','templateCalls','requestTokenizations','issues','begins'])
    assert result['modelLoads']==1 and result['traces'][0]['offsets'][0]>0
    assert result['replayedBeforeNative']>=saved['hostHigh']-saved['client']['high']
    assert [x['bytes'] for x in result['inbox'][:len(saved['inbox'])]]==[x['bytes'] for x in saved['inbox']]
    return result,item

try:
    if DENIED and not ACTION.startswith('cleanup'):
        probes=[INPUTS/'request.json',INPUTS/(LANE+'-primary-prepared.json'),INPUTS/(LANE+'-primary-configuration.json'),INPUTS/(LANE+'-primary-export.json')]
        if MODEL_DENIED:probes.append(model(LANE)/('profile.json' if LANE=='normal' else 'configuration.json'))
        refused=[]
        for probe in probes:
            try:fd=os.open(probe,os.O_RDONLY|os.O_NOFOLLOW);os.close(fd)
            except PermissionError:refused.append(str(probe.relative_to(BASE)))
            else:raise AssertionError('selected read denial did not apply')
        event(PHASE+'-read-denial-probes',dict(refused=refused,noContentsRead=True))
    if ACTION=='feasibility':feasibility()
    elif ACTION=='original-primary':
        pair=original(LANE+'-primary',(600,900));data,item=run(pair,LANE+'-primary-probe',original=True,allowed='probe')
        event(LANE+'-actual-probe-checkpoint',dict(report=data,workerPID=item['pid'],exitCode=item['exitCode'],joined=item['joined']))
    elif ACTION=='resume-probe':
        pair=load(LANE+'-primary');assert boot()!=pair['boot'] and hashes(pair)==pair['checkpointHashes']
        result,item=resumed(pair,LANE+'-primary-probe-resumed','guided',pair['checkpoint'])
        prepared=[s for s in steps(result,LANE+'-primary-probe-resumed') if s['operation']=='next-pass']
        assert len(prepared)==1
        selected=prepared[0]['progress']['current']
        assert selected['kind']==('schema' if LANE=='normal' else 'tool')
        assert prepared[0]['nativeCalls']==(len(selected['tokens'])+255)//256
        assert prepared[0]['traces'][0]['offsets'][0]==0
        if LANE=='normal':
            assert result['repairEncodes']==0 and selected['tokens']==result['provider']['lane']['allowed']['_0']['originalTokens']
            assert selected['index']==0 and not selected.get('proposalID') and selected['messagesDigest']==hashlib.sha256(b'').hexdigest()
        else:assert result['repairEncodes']>0
        event(LANE+'-actual-probe-postboot',dict(report=result,workerPID=item['pid'],joined=item['joined'],exactRestore=True))
    elif ACTION=='resume-guided':
        pair=load(LANE+'-primary');assert boot()!=pair['guidedBoot'] and hashes(pair)==pair['checkpointHashes']
        saved=pair['guidedCheckpoint'];result,item=resumed(pair,LANE+'-primary-guided-resumed','ready',saved)
        assert result['modelPrepares']==0
        assert not [s for s in steps(result,LANE+'-primary-guided-resumed') if s['operation'] in ['prepare','next-pass']]
        assert result['repairEncodes']==0 if LANE=='normal' else result['repairEncodes']>0
        progress=[s['progress'] for s in steps(result,LANE+'-primary-guided-resumed')];old=saved['allowedProgress']['guided']
        for step in range(1,old['pendingTokens']+1):
            current=progress[step]['guided']
            assert current['sampledTokens']==old['sampledTokens'] and current['forcedTokens']==old['forcedTokens']+step
            assert current['accepts']==old['accepts'] and current['pendingTokens']==old['pendingTokens']-step
        end=result['allowedProgress']
        assert json.loads(base64.b64decode(end['whole']))==({'value':'中'} if LANE=='normal' else {'name':'a','arguments':{'n':7}})
        pair['ready']=result;savepair(pair)
        event(LANE+'-actual-guided-postboot-ready',dict(report=result,savedForcedSuffixConsumedBeforeResampling=True,workerPID=item['pid'],joined=item['joined']))
    elif ACTION=='ready-primary':
        pair=load(LANE+'-primary');result,item=run(pair,LANE+'-primary-ready-emission',allowed='emitted')
        assert result['allowedInitial']==pair['ready']['allowedProgress'] and result['allowedProgress']['phase']=='finalEmitted'
        assert result['nativeCalls']==result['modelPrepares']==0 and result['modelLoads']==1
        assert result['client']['high']==pair['ready']['hostHigh'] and result['hostHigh']==result['client']['high']+(3 if LANE=='fixture' else 2)
        assert result['replayedBeforeNative']==pair['ready']['hostHigh']-pair['ready']['client']['high']
        assert result['beforeInbox']==pair['ready']['inbox']
        assert result['client']['registrations']==0 and not result['client']['terminal']
        pair['emitted']=result;savepair(pair);event(LANE+'-fresh-ready-zero-forward-emission',result)
    elif ACTION=='terminal-primary':
        pair=load(LANE+'-primary');result,item=run(pair,LANE+'-primary-terminal-replay')
        assert result['client']['terminal'] and result['client']['registrations']==(1 if LANE=='fixture' else 0)
        assert result['nativeCalls']==result['modelLoads']==0 and not result['traces'] and not result['allowedSteps']
        assert result['replayedBeforeNative']==pair['emitted']['hostHigh']-pair['emitted']['client']['high']
        assert result['selectedCommit']==pair['emitted']['selectedCommit'] and not result.get('allowedProgress')
        pair['terminal']=result;savepair(pair);event(LANE+'-terminal-model-reads-denied',result)
    elif ACTION=='duplicate-primary':
        pair=load(LANE+'-primary');result,item=run(pair,LANE+'-primary-duplicate-replay',duplicate=True)
        assert result['duplicateExact'] and result['client']==pair['terminal']['client']
        assert result['inbox']==result['beforeInbox']==pair['terminal']['inbox']
        assert result['nativeCalls']==result['modelLoads']==0 and result['selectedCommit']==pair['terminal']['selectedCommit']
        event(LANE+'-fresh-client-exact-duplicate',result)
    elif ACTION=='retire-primary':retire(load(LANE+'-primary'))
    elif ACTION=='reference':
        pair=original(LANE+'-reference',(600,900));result,item=run(pair,LANE+'-reference-uninterrupted',original=True)
        primary=load(LANE+'-primary');terminal=primary['terminal']
        assert pair['originals']['pin']!=primary['originals']['pin']
        assert result['provider']==terminal['provider'] and result['client']['terminal'] and result['client']['registrations']==(1 if LANE=='fixture' else 0)
        assert [x['bytes'] for x in result['inbox']]==[x['bytes'] for x in terminal['inbox']]
        assert result['originalBoot']==result['receiverBoot'] and result['admission']!=terminal['admission']
        assert result['allowedProgress']==primary['emitted']['allowedProgress']
        split=[primary['checkpoint'],primary['guidedCheckpoint'],primary['ready'],primary['emitted']]
        def nativeTrace(reports):
            return [(t['kind'],t['index'],offset,digest) for report in reports for t in report['traces'] for offset,digest in zip(t['offsets'],t['inputDigests'])]
        assert nativeTrace(split)==nativeTrace([result]) and sum(x['nativeCalls'] for x in split)==result['nativeCalls']
        event(LANE+'-exact-independent-reference',dict(exactNativeEventBytes=True,exactPerPassNativeOffsetsAndInputs=True,
            primaryAdmission=terminal['admission'],referenceAdmission=result['admission'],report=result))
        retire(pair)
    elif ACTION=='faults':
        assert LANE=='normal'
        pair=original(LANE+'-faults',(180,240));active,_=run(pair,'normal-fault-route-cut',original=True,allowed='route-ready')
        _,item=run(pair,'normal-after-schema-pass-delay',fault='after-next-pass-native',boundary='delay',expected=1)
        point=next(x for x in item['frames'] if x['stage']=='boundary')
        assert point['allowed']==active['allowedProgress'] and point['allowed']['phase']=='routeReady'
        assert item['seconds']>=11 and item['frames'][-1]['nativeCalls']==point['nativeCalls']==2
        assert point['allowed']['route']=='schema' and point['allowedOperation']=='next-pass'
        trace=next(t for t in point['traces'] if t['kind']=='schema')
        assert trace['calls']==2 and trace['offsets'][0]==0 and trace['preparedTokens']==active['provider']['lane']['allowed']['_0']['originalTokens']
        event('schema-after-next-pass-eleven-second-refusal',dict(nativeCalls=2,noPublication=True,seconds=item['seconds'],
            activeAllowed=point['allowed'],schemaPrefill=trace,lastAcceptedCommit=active['selectedCommit'],diskState='requires-authenticated-reconciliation',
            rejectedClockObservation=None,rejectedClockObservationScope='No rejected numerical clock sample is exposed by the existing action.check refusal. Delay and observed native work are retained.'))
        retire(pair)
    elif ACTION.startswith('cleanup'):
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
