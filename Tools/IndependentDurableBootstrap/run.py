#!/usr/bin/env python3
from pathlib import Path
import os,sys,json,subprocess,signal,time,shutil,hashlib,socket,argparse,re,stat
parser=argparse.ArgumentParser(description="Qualify separate normal reachd host/client processes on owned loopback.")
parser.add_argument('--scratch',type=Path,required=True,help='Existing owned /private/tmp/reach-s95.* directory')
parser.add_argument('--label',required=True,help='Fresh qualification directory suffix')
parser.add_argument('--executable',type=Path,required=True,help='Built normal reachd executable')
parser.add_argument('--metallib',type=Path,required=True,help='Verified normal-build Metal resource')
parser.add_argument('--model',type=Path,required=True)
parser.add_argument('--public-model',type=Path,required=True)
parser.add_argument('--requests',type=Path,required=True)
parser.add_argument('--mode',choices=['reference','crash','client-restart','lost-receipt','retention-exhaustion'],required=True)
parser.add_argument('--reference',type=Path,help='Prior reference qualification directory, required for crash mode')
parser.add_argument('routes',nargs='+',choices=['ordinary','guided','required','allowed','combined'])
args=parser.parse_args()
base=args.scratch.resolve(strict=True)
assert str(base).startswith('/private/tmp/reach-s95.') and base.stat().st_uid==os.getuid() and stat.S_IMODE(base.stat().st_mode)==0o700
assert re.fullmatch('[a-z0-9-]{1,64}',args.label)
assert args.mode=='reference' or args.reference is not None
assert args.mode in ['reference','crash'] or args.routes==['ordinary']
run=base/('qualification-'+args.label);run.mkdir(mode=0o700)
for name in ('bin','reports','logs','roots','staging'):(run/name).mkdir(mode=0o700)
exe=run/'bin/reachd';shutil.copyfile(args.executable,exe);exe.chmod(0o700)
shutil.copyfile(args.metallib,run/'bin/mlx.metallib')
assert exe.stat().st_size <=192<<20
profile='(version 1)(allow default)(deny network*)(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*"))(allow network-outbound (remote ip "localhost:*"))'
mode=args.mode
evidence={'mode':mode,'sourceExecutable':str(args.executable.resolve()),'metalSHA256':hashlib.sha256(args.metallib.read_bytes()).hexdigest(),'executable':str(exe),'sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'processes':[],'cells':[]};children=[]
def sample():
 allocated=0
 for item in [base,*base.rglob('*')]:
  try:allocated+=item.lstat().st_blocks*512
  except FileNotFoundError:pass
 free=shutil.disk_usage(base).free
 assert allocated<=32<<30 and free>=20<<30
 evidence.setdefault('resources',[]).append({'allocated':allocated,'free':free})
def save():(run/'evidence.json').write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')
class Child:
 def __init__(self,label,args,denied=None):
  self.label=label;self.events=[];self.buffer=b'';self.joined=False
  self.out=(run/'logs'/(label+'.stdout')).open('wb');self.err=(run/'logs'/(label+'.stderr')).open('wb')
  confinement=profile+((' (deny file-read* file-write* (subpath '+json.dumps(str(denied))+'))') if denied else '')
  self.args=['/usr/bin/sandbox-exec','-p',confinement,str(exe),*args]
  self.p=subprocess.Popen(self.args,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True);os.set_blocking(self.p.stdout.fileno(),False)
  self.record={'label':label,'pid':self.p.pid,'command':self.args,'joined':False};evidence['processes'].append(self.record);children.append(self);save()
 def drain(self):
  if self.joined:return
  try:data=os.read(self.p.stdout.fileno(),65536)
  except BlockingIOError:return
  self.out.write(data);self.out.flush();self.buffer+=data
  while b'\n' in self.buffer:
   line,self.buffer=self.buffer.split(b'\n',1)
   try:self.events.append(json.loads(line))
   except (ValueError,UnicodeDecodeError):pass
  assert self.out.tell()<=192<<20 and self.err.tell()<=192<<20
 def until(self,predicate,timeout=180):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   for child in children:child.drain()
   while self.events:
    value=self.events.pop(0)
    if predicate(value):return value
   if self.p.poll() is not None:return None
   time.sleep(.0005)
  raise TimeoutError(self.label)
 def join(self,timeout=180):
  if self.joined:return self.p.returncode
  self.until(lambda _:False,timeout);code=self.p.wait(timeout=2);self.drain()
  self.record.update(exit_code=code,joined=True);self.joined=True
  self.out.close();self.err.close();self.p.stdout.close();save();return code
 def kill(self):
  if self.p.poll() is None:self.p.kill()
  return self.join()
 def stop(self):
  if self.p.poll() is None:self.p.send_signal(signal.SIGTERM)
  return self.join(30)
def port():
 for value in range(54194,54294):
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   try:s.bind(('127.0.0.1',value));return value
   except OSError:pass
 raise RuntimeError('no selected port')
def command(label,args,expected=0,denied=None):
 child=Child(label,args,denied=denied)
 try:code=child.join()
 finally:
  if child.p.poll() is None:child.kill()
 assert code==expected,(label,code);return child
try:
 sample()
 for route in args.routes:
  hostroot=run/'roots'/(route+'-host');clientroot=run/'roots'/(route+'-client');selected=port()
  staging=run/'staging'/route
  command(route+'-provision',['durable-independent','provision','--public-model',str(args.public_model),'--output',str(staging),'--port',str(selected)]+(['--retention-seconds','3'] if mode=='retention-exhaustion' else []))
  guardians=[];host=client=None
  try:
   greetings=[]
   for role,own,peer in [('host',hostroot,clientroot),('client',clientroot,hostroot)]:
    initargs=['durable-independent','init','--role',role,'--root',str(own),'--provisioned',str(staging/role)]
    if role=='host':initargs+=['--model',str(args.model)]
    guardian=Child(route+'-'+role+'-init',initargs,denied=peer);guardians.append(guardian)
    greeting=guardian.until(lambda v:v.get('stage')=='ready',30);assert greeting,(route,role,'initializer not ready')
    greetings.append(greeting)
   assert greetings[0]['epoch']!=greetings[1]['epoch'] and greetings[0]['origin']!=greetings[1]['origin']
   ready=[json.loads((own/'bootstrap/ready.json').read_text()) for own in [hostroot,clientroot]]
   assert ready[0]['core']['container']!=ready[1]['core']['container']
   assert [v['core']['keys'][0]['role'] for v in ready]==['host-catalog','client-metadata']
   (run/'reports'/(route+'-roles.json')).write_text(json.dumps({'ready':ready,'greetings':greetings},sort_keys=True,indent=2)+'\n')
   # A separate cooperative probe observes direct kernel filesystem denial.
   # Runtime workers use this identical policy; securityd IPC is not a sandbox claim.
   probes=[]
   for own,peer in [(hostroot,clientroot),(clientroot,hostroot)]:
    confinement=profile+' (deny file-read* file-write* (subpath '+json.dumps(str(peer))+'))'
    script="from pathlib import Path;import sys;own,peer=map(Path,sys.argv[1:]);assert (own/'agreement.json').read_bytes();denied=[]\nfor op in [lambda:(peer/'agreement.json').read_bytes(),lambda:(peer/'denied-write').write_bytes(b'x')]:\n try:op()\n except PermissionError:denied.append(True)\nassert len(denied)==2;print('own read PASS; peer read/write DENIED')"
    cmd=['/usr/bin/sandbox-exec','-p',confinement,'/usr/bin/python3','-c',script,str(own),str(peer)]
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
    probes.append({'command':cmd,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'joined':True})
    assert result.returncode==0,result.stderr
   (run/'reports'/(route+'-filesystem.json')).write_text(json.dumps(probes,sort_keys=True,indent=2)+'\n')
   shutil.rmtree(staging);assert not staging.exists()
   evidence.setdefault('provisioningRemoved',[]).append(str(staging));save()
   sample();print(route,'independent ready',flush=True)
   hostreport=run/'reports'/(route+'-host.json');clientreport=run/'reports'/(route+'-client.json')
   host=Child(route+'-host',['durable-independent','host','--root',str(hostroot),'--report',str(hostreport),'--progress'],denied=clientroot)
   assert host.until(lambda v:v.get('stage')=='listening',30),(route,'host not listening')
   binding=subprocess.run(['/usr/sbin/lsof','-nP','-a','-p',str(host.p.pid),'-iUDP'],capture_output=True,text=True)
   (run/'reports'/(route+'-socket.txt')).write_text(binding.stdout+binding.stderr)
   assert '127.0.0.1:'+str(selected) in binding.stdout and '*:'+str(selected) not in binding.stdout,binding.stdout
   client=Child(route+'-client',['durable-independent','begin','--root',str(clientroot),'--request',str(args.requests/(route+'.json')),'--report',str(clientreport),'--progress'],denied=hostroot)
   cut=None
   if mode.startswith('crash'):
    assert client.until(lambda v:v.get('stage')=='registered',30),(route,'client not registered')
    cut=host.until(lambda v:v.get('stage')=='boundary' and v.get('nativeCalls',0)>=8 and (v.get('high')==0 if route in ['required','combined'] else v.get('high',0)>0) and 'terminal' not in v.get('checkpoint',''),60)
    assert cut,(route,'no qualified cut')
    host.p.send_signal(signal.SIGSTOP)
    stopped,code=os.waitpid(host.p.pid,os.WUNTRACED);assert stopped==host.p.pid and os.WIFSTOPPED(code)
    host.kill();assert client.p.poll() is None and all(g.p.poll() is None for g in guardians)
    old=host.p.pid
    host=Child(route+'-host-restart',['durable-independent','host','--root',str(hostroot),'--report',str(hostreport),'--progress'],denied=clientroot)
    assert host.until(lambda v:v.get('stage')=='listening',30),(route,'restart not listening')
    cut.update(oldHostPID=old,newHostPID=host.p.pid,survivingClientPID=client.p.pid,initializerPIDs=[g.p.pid for g in guardians])
    print(route,'cut',cut,flush=True)
   if mode in ['client-restart','lost-receipt','retention-exhaustion']:
    cut=client.until(lambda v:v.get('stage')=='batch-persisted' and v.get('high',0)>=4,60);assert cut
    client.p.send_signal(signal.SIGSTOP)
    stopped,code=os.waitpid(client.p.pid,os.WUNTRACED);assert stopped==client.p.pid and os.WIFSTOPPED(code)
    client.drain()
    rows=[json.loads(line) for line in (run/'logs'/(route+'-client.stdout')).read_text().splitlines() if line.startswith('{')]
    persisted=max([v.get('high',0) for v in rows if v.get('stage')=='batch-persisted'],default=0)
    acknowledged=max([v.get('high',0) for v in rows if v.get('stage')=='receipt-accepted'],default=0)
    cut.update(persisted=persisted,acknowledged=acknowledged)
    if mode=='client-restart':
     old=client.p.pid;client.kill();clientreport=run/'reports'/(route+'-recovered-client.json')
     client=Child(route+'-recovered-client',['durable-independent','recover','--root',str(clientroot),'--report',str(clientreport),'--progress'],denied=hostroot)
     cut.update(oldClientPID=old,newClientPID=client.p.pid,survivingHostPID=host.p.pid)
    else:
     if mode=='lost-receipt':assert persisted>acknowledged,('cut raced receipt acceptance',cut)
     assert host.stop()==0
     client.p.send_signal(signal.SIGCONT)
     if mode=='retention-exhaustion':
      start=time.monotonic();assert client.join(20)==1
      h=json.loads(hostreport.read_text())
      # The final content publication gate refuses even cached acceptance/prefix bytes.
      assert not clientreport.exists(), 'expired client published a new report'
      assert 'TransportRuntimeError' in (run/'logs'/(route+'-client.stderr')).read_text()
      elapsed=time.monotonic()-start;assert elapsed<10
      assert h['requestPreparations']==1 and h['issues']==1 and h['begins']==1
      evidence['cells'].append({'route':route,'seam':mode,'result':'PASS','cut':cut,'retentionSeconds':3,'boundedExitSeconds':elapsed,'replacementWork':False,'fabricatedEnding':False,'reportPublicationRefused':True})
      save();print(mode,'bounded refusal',elapsed,flush=True);continue
     hostreport=run/'reports'/(route+'-restart-host.json')
     host=Child(route+'-restart-host',['durable-independent','host','--root',str(hostroot),'--report',str(hostreport),'--progress'],denied=clientroot)
     assert host.until(lambda v:v.get('stage')=='listening',30)
   assert client.join(240)==0,(route,'client failed')
   assert host.stop()==0,(route,'host stop failed')
   result=json.loads(clientreport.read_text());h=json.loads(hostreport.read_text())
   assert result['terminal'] and result['registered'],result['stage']
   pins=json.loads((hostroot/'host/selection.json').read_text())['pins']
   assert h['peerDigests']==[pins['clientLeaf']] and result['peerDigests']==[pins['hostLeaf']]
   (run/'reports'/(route+'-pins.json')).write_text(json.dumps(pins,sort_keys=True)+'\n')
   assert result['acquisition']['storageLoads']==['client-metadata'],result['acquisition']
   assert h['acquisition']['modelLoads']==1,h
   if mode.startswith('crash'):
    assert h['nativeCalls']>0 and result['reconnects']>=1,h
    assert all(h[k]==0 for k in ['requestPreparations','templateCalls','requestTokenizations','issues','begins']),h
    assert h['traces'][0]['prepares']==0 and h['traces'][0]['offsets'][0]>0,h['traces']
    reference=args.reference/'reports'
    previous=json.loads((reference/(route+'-client.json')).read_text());previousHost=json.loads((reference/(route+'-host.json')).read_text())
    assert result['inbox']==previous['inbox'],(route,'inbox mismatch')
    assert h['binding']==previousHost['binding'],(route,'binding mismatch')
   elif mode in ['client-restart','lost-receipt']:
    previous=json.loads((args.reference/'reports'/(route+'-client.json')).read_text())
    assert result['inbox']==previous['inbox'] and result['beforeRecovery'] and result['beforeRecovery'][0]
    if mode=='lost-receipt':assert all(h[k]==0 for k in ['requestPreparations','templateCalls','requestTokenizations','issues','begins'])
    else:assert h['requestPreparations']==1
   else:assert h['requestPreparations']==1,h
   # Fresh client and host replay the terminal solely from committed authority.
   replay=run/'reports'/(route+'-terminal-client.json');terminalHost=run/'reports'/(route+'-terminal-host.json')
   host=Child(route+'-terminal-host',['durable-independent','host','--root',str(hostroot),'--report',str(terminalHost),'--progress'],denied=clientroot)
   assert host.until(lambda v:v.get('stage')=='listening',30)
   command(route+'-terminal-client',['durable-independent','recover','--root',str(clientroot),'--report',str(replay)],denied=hostroot)
   assert host.stop()==0
   terminal=json.loads(replay.read_text());th=json.loads(terminalHost.read_text())
   assert terminal['inbox']==result['inbox'] and th['nativeCalls']==0,(route,'terminal replay')
   retention=result['retention'];assert terminal['retention']==retention
   assert retention['policy']=='role-monotonic-ns-v1:'+ready[1]['core']['epoch']
   assert retention['hostPolicy']=='role-monotonic-ns-v1:'+ready[0]['core']['epoch']
   assert retention['boot']==ready[1]['core']['boot'] and retention['hostBoot']==ready[0]['core']['boot']
   assert retention['context']==result['accepted']['contextDigest']
   assert retention['deadline']>retention['anchor'] and retention['deadline']-retention['anchor']<=retention['cap']
   evidence['cells'].append({'route':route,'result':'PASS','high':result['high'],'hostNativeCalls':h['nativeCalls'],'port':selected,'cut':cut,'terminalReplay':True});save();print(route,'settled',result['high'],h['nativeCalls'],flush=True)
  finally:
   if client and client.p.poll() is None:client.p.send_signal(signal.SIGCONT)
   for child in (client,host):
    if child and not child.joined:
     try:child.stop()
     except Exception:child.kill()
   for guardian in reversed(guardians):
    if guardian.p.poll() is None:
     guardian.p.send_signal(signal.SIGTERM)
     retired=guardian.until(lambda v:v.get('stage') in ['retired','cleanup-blocked'],30)
     if not retired or retired['stage']!='retired':raise RuntimeError('Original initializer retains cleanup authority: '+str(guardian.p.pid))
    assert guardian.join(30)==0
   assert not hostroot.exists() and not clientroot.exists()
   if staging.exists():shutil.rmtree(staging)
 sample();evidence['result']='PASS';save()
except BaseException as error:
 evidence['result']='FAIL';evidence['failure']=repr(error);save();raise
