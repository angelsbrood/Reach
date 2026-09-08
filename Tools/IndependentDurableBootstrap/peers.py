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
parser.add_argument('--test-bundle',type=Path,required=True)
parser.add_argument('--mode',choices=['reference','crash','client-restart','lost-receipt','retention-exhaustion'],required=True)
parser.add_argument('--reference',type=Path,help='Prior reference qualification directory, required for crash mode')
parser.add_argument('routes',nargs='+',choices=['ordinary','guided','required','allowed','combined'])
args=parser.parse_args()
assert args.mode=='reference' and args.routes==['ordinary']
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
 route='ordinary';hostroot=run/'roots'/'host';clientroot=run/'roots'/'client';selected=port();staging=run/'staging'/'pair'
 command('provision',['durable-independent','provision','--public-model',str(args.public_model),'--output',str(staging),'--port',str(selected)])
 guardians=[];host=client=None
 try:
  for role,own,peer in [('host',hostroot,clientroot),('client',clientroot,hostroot)]:
   initargs=['durable-independent','init','--role',role,'--root',str(own),'--provisioned',str(staging/role)]
   if role=='host':initargs+=['--model',str(args.model)]
   g=Child(role+'-init',initargs,denied=peer);guardians.append(g)
   assert g.until(lambda v:v.get('stage')=='ready',30)
  shutil.rmtree(staging);assert not staging.exists();sample()
  # Every changed untrusted selection is restored byte-for-byte while its
  # original creator remains alive. No denial invokes a replacement initializer.
  for label,path,change in [
   ('pair',clientroot/'agreement.json',lambda x:x.update(pair='00000000-0000-0000-0000-000000000001')),
   ('descriptor',clientroot/'client/selection.json',lambda x:x['descriptor'].update(model='foreign')),
   ('role',clientroot/'bootstrap/ready.json',lambda x:x['core'].update(role='host')),
   ('confirmation',clientroot/'bootstrap/ready.json',lambda x:x.update(confirmations=['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=']))]:
   original=path.read_bytes();value=json.loads(original);change(value)
   try:
    path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
    command('refuse-'+label,['durable-independent','recover','--root',str(clientroot)],expected=1,denied=hostroot)
   finally:path.write_bytes(original)
  archive=clientroot/'client/identity.p12';original=archive.read_bytes()
  try:
   archive.write_bytes((hostroot/'host/identity.p12').read_bytes())
   command('refuse-archive',['durable-independent','recover','--root',str(clientroot)],expected=1,denied=hostroot)
  finally:archive.write_bytes(original)
  command('refuse-role-root',['durable-independent','host','--root',str(clientroot)],expected=1,denied=hostroot)
  command('refuse-mode',['durable-transport','recover','--root',str(clientroot)],expected=1,denied=hostroot)
  def peer(name):
   confinement=profile+' (deny file-read* file-write* (subpath '+json.dumps(str(hostroot))+'))'
   env=dict(os.environ,S95_PEER_ROOT=str(clientroot),S93_TEST_ROOT=str(args.model.parent))
   cmd=['/usr/bin/sandbox-exec','-p',confinement,'/usr/bin/xcrun','xctest','-XCTest','ReachDurableRuntimeTests.TransportPeerTests/'+name,str(args.test_bundle)]
   with (run/'logs'/(name+'.log')).open('wb') as output:
    process=subprocess.Popen(cmd,env=env,stdout=output,stderr=subprocess.STDOUT)
    record={'label':name,'pid':process.pid,'command':cmd,'joined':False};evidence['processes'].append(record);save()
    try:code=process.wait(timeout=90)
    except BaseException:
     process.kill();process.wait();raise
    finally:record.update(joined=True,exit_code=process.returncode);save()
   assert code==0,(name,code)
  report=run/'reports'/'pre-work-host.json'
  host=Child('pre-work-host',['durable-independent','host','--root',str(hostroot),'--report',str(report),'--progress'],denied=clientroot)
  assert host.until(lambda v:v.get('stage')=='listening',30)
  for test in ['testOldDialectAndPreHelloDurableFramesRefuse','testConfiguredProfileMismatchBeforeOriginalIssue','testUnsolicitedTerminalReceiptRefuses']:peer(test)
  assert host.stop()==0
  before=json.loads(report.read_text());assert before['nativeCalls']==0 and before['issues']==0 and before['begins']==0 and not before['reserved']
  report=run/'reports'/'withheld-host.json'
  host=Child('withheld-host',['durable-independent','host','--root',str(hostroot),'--report',str(report),'--progress'],denied=clientroot)
  assert host.until(lambda v:v.get('stage')=='listening',30)
  peer('testWithholdReceiptAfterUnregisteredBegin');assert host.stop()==0
  h=json.loads(report.read_text());assert h['reserved'] and h['issues']==1 and h['begins']==1 and h['requestPreparations']==1
  assert len(h['batches'])==1 and h['nativeCalls']>0 and h.get('providerEnding') is None
  command('refuse-incomplete-registration',['durable-independent','recover','--root',str(clientroot)],expected=1,denied=hostroot)
  report=run/'reports'/'reservation-restart.json'
  host=Child('reservation-restart',['durable-independent','host','--root',str(hostroot),'--report',str(report),'--progress'],denied=clientroot)
  assert host.until(lambda v:v.get('stage')=='listening',30)
  command('refuse-replacement',['durable-independent','begin','--root',str(clientroot),'--request',str(args.requests/'ordinary.json')],expected=1,denied=hostroot)
  assert host.stop()==0
  h=json.loads(report.read_text());assert h['reserved'] and all(h[k]==0 for k in ['nativeCalls','issues','begins','requestPreparations'])
  report=run/'reports'/'cancel.json'
  command('cancel',['durable-independent','cancel','--root',str(hostroot),'--report',str(report)],denied=clientroot)
  h=json.loads(report.read_text());assert h['disposition']=='cancelled' and h.get('providerEnding') is None and h['nativeCalls']==0
  evidence['cells'].append({'result':'PASS','seams':['role','pair','descriptor','archive','confirmation','mode','profile','old-offers','one-outstanding-batch','incomplete-registration','reservation-restart','host-local-cancel'],'keychainObservation':'cooperative exact role selectors; direct filesystem denial excludes securityd IPC'})
 finally:
  for child in (client,host):
   if child and not child.joined:
    try:child.stop()
    except Exception:child.kill()
  for g in reversed(guardians):
   if g.p.poll() is None:
    g.p.send_signal(signal.SIGTERM);retired=g.until(lambda v:v.get('stage') in ['retired','cleanup-blocked'],30)
    if not retired or retired['stage']!='retired':raise RuntimeError('Original initializer retains cleanup authority: '+str(g.p.pid))
   assert g.join(30)==0
  assert not hostroot.exists() and not clientroot.exists()
 sample();evidence['result']='PASS';save()
except BaseException as error:
 evidence['result']='FAIL';evidence['failure']=repr(error);save();raise
