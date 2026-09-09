from pathlib import Path
import argparse,hashlib,json,os,shutil,signal,socket,stat,subprocess,time

NETWORK='(version 1)(allow default)(deny network*)(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*"))(allow network-outbound (remote ip "localhost:*"))'
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def parser(description):
 p=argparse.ArgumentParser(description=description)
 for name in ['scratch','executable','metallib','model','public-model','requests']:p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--label',required=True)
 return p
class Child:
 def __init__(self,campaign,label,arguments,denied=(),program=None,network=True,descriptors=()):
  self.c=campaign;self.label=label;self.events=[];self.buffer=b'';self.joined=False;self.stopped=False
  profile=NETWORK if network else '(version 1)(allow default)(deny network*)'
  for path in denied:profile+=' (deny file-read* file-write* (subpath '+json.dumps(str(path))+'))'
  command=['/usr/bin/sandbox-exec','-p',profile,str(program or campaign.exe),*map(str,arguments)]
  self.out=(campaign.run/'logs'/(label+'.stdout')).open('xb');self.err=(campaign.run/'logs'/(label+'.stderr')).open('xb')
  self.p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True,pass_fds=tuple(descriptors));os.set_blocking(self.p.stdout.fileno(),False)
  self.record={'label':label,'pid':self.p.pid,'command':command,'joined':False};campaign.children.append(self);campaign.e['processes'].append(self.record);campaign.save()
 def drain(self):
  if self.joined:return
  while True:
   try:data=os.read(self.p.stdout.fileno(),65536)
   except BlockingIOError:return
   if not data:return
   self.out.write(data);self.out.flush();self.buffer+=data
   while b'\n' in self.buffer:
    line,self.buffer=self.buffer.split(b'\n',1)
    try:self.events.append(json.loads(line))
    except (ValueError,UnicodeDecodeError):pass
   assert self.out.tell()<=192<<20 and self.err.tell()<=192<<20
 def until(self,predicate,timeout=180):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   for child in self.c.children:child.drain()
   while self.events:
    event=self.events.pop(0)
    if predicate(event):return event
   if self.p.poll() is not None:return None
   time.sleep(.0005)
  raise TimeoutError(self.label)
 def join(self,timeout=180):
  if self.joined:return self.record['exit_code']
  try:self.until(lambda _:False,timeout)
  finally:
   if self.p.poll() is None:
    self.resume();self.p.kill()
   code=self.p.wait();self.drain();self.record.update(joined=True,exit_code=code)
   self.joined=True;self.out.close();self.err.close();self.p.stdout.close();self.c.save()
  return code
 def pause(self):
  self.p.send_signal(signal.SIGSTOP);pid,value=os.waitpid(self.p.pid,os.WUNTRACED)
  assert pid==self.p.pid and os.WIFSTOPPED(value);self.stopped=True;self.drain()
 def resume(self):
  if self.stopped and self.p.poll() is None:self.p.send_signal(signal.SIGCONT)
  self.stopped=False
 def stop(self):
  if self.p.poll() is None:self.resume();self.p.send_signal(signal.SIGTERM)
  return self.join(30)
 def kill(self):
  if self.p.poll() is None:self.p.kill()
  return self.join(30)
class Campaign:
 def __init__(self,args):
  self.args=args;self.base=args.scratch.resolve(strict=True)
  assert str(self.base).startswith('/private/tmp/reach-s96.') and stat.S_IMODE(self.base.stat().st_mode)==0o700 and self.base.stat().st_uid==os.getuid()
  assert args.label and all(x.islower() or x.isdigit() or x=='-' for x in args.label)
  self.run=self.base/('qualification-'+args.label);self.run.mkdir(mode=0o700)
  for name in ['bin','logs','reports','roots','controls','staging']:(self.run/name).mkdir(mode=0o700)
  self.exe=self.run/'bin/reachd';shutil.copyfile(args.executable,self.exe);self.exe.chmod(0o700)
  shutil.copyfile(args.metallib,self.run/'bin/mlx.metallib')
  self.children=[];self.roles=[]
  self.e={'executable':str(self.exe),'sha256':digest(self.exe),'metalSHA256':digest(args.metallib),'processes':[],'cells':[]}
  self.sample();self.save()
 def save(self):(self.run/'evidence.json').write_text(json.dumps(self.e,sort_keys=True,indent=2)+'\n')
 def sample(self):
  allocated=0
  for path in [self.base,*self.base.rglob('*')]:
   try:allocated+=path.lstat().st_blocks*512
   except FileNotFoundError:pass
  free=shutil.disk_usage(self.base).free
  self.e.setdefault('resources',[]).append({'allocated':allocated,'free':free});self.save()
  assert allocated<=32<<30 and free>=20<<30
 def child(self,label,arguments,**kwargs):return Child(self,label,arguments,**kwargs)
 def command(self,label,arguments,expected=0,**kwargs):
  child=self.child(label,arguments,**kwargs)
  assert child.join()==expected,(label,child.record.get('exit_code'))
  return child
 def port(self):
  for value in range(54194,54294):
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    try:sock.bind(('127.0.0.1',value));return value
    except OSError:pass
  raise RuntimeError('No selected loopback port')
 def initialize(self,label,roles=('host','client'),retention=86400):
  port=self.port();staging=self.run/'staging'/label
  self.command(label+'-provision',['durable-independent','provision','--public-model',self.args.public_model,'--output',staging,'--port',port,'--retention-seconds',retention])
  selected={}
  for role in roles:
   root=self.run/'roots'/(label+'-'+role);control=self.run/'controls'/(label+'-'+role);control.mkdir(mode=0o700)
   peer='client' if role=='host' else 'host'
   denied=[self.run/'roots'/(label+'-'+peer),self.run/'controls'/(label+'-'+peer)]
   receipt=control/'owner.json'
   arguments=['durable-independent','init','--finish','--owner-receipt',receipt,'--role',role,'--root',root,'--provisioned',staging/role]
   if role=='host':arguments+=['--model',self.args.model]
   creator=self.command(label+'-'+role+'-init',arguments,denied=denied)
   rows=[json.loads(line) for line in (self.run/'logs'/(creator.label+'.stdout')).read_text().splitlines() if line.startswith('{')]
   greeting=next(v for v in rows if v.get('stage')=='ready');expected=greeting['ownerReceiptDigest']
   ready=json.loads((root/'bootstrap/ready.json').read_text());ownership=json.loads(receipt.read_text())
   assert ready['core']['version']==2 and ownership['ready']==ready and ready['core']['lifecycle']['receipt']==str(receipt)
   assert creator.joined and creator.p.returncode==0 and stat.S_IMODE(receipt.stat().st_mode)==0o600
   item={'role':role,'root':root,'control':control,'receipt':receipt,'digest':expected,'ready':ready,'greeting':greeting,'denied':denied,'initializerPID':creator.p.pid,'retired':False}
   self.roles.append(item);selected[role]=item
  shutil.rmtree(staging);assert not staging.exists()
  self.e.setdefault('provisioningRemoved',[]).append(str(staging));self.save()
  (self.run/'reports'/(label+'-roles.json')).write_text(json.dumps({k:{'ready':v['ready'],'greeting':v['greeting'],'initializerPID':v['initializerPID']} for k,v in selected.items()},sort_keys=True,indent=2)+'\n')
  return selected,port
 def retire(self,label,role,expected=0):
  child=self.command(label,['durable-independent','retire','--owner-receipt',role['receipt'],'--expected-digest',role['digest']],expected=expected,denied=role['denied'])
  if expected==0:
   assert not role['root'].exists();role['retired']=True
  return child
 def finish(self,error=None):
  cleanup=[]
  for child in self.children:
   if not child.joined:
    try:child.stop()
    except BaseException as problem:cleanup.append(repr(problem));child.kill()
  for role in reversed(self.roles):
   if not role['retired'] and not role.get('fixtureDisposed',False):
    try:self.retire('cleanup-'+role['root'].name,role)
    except BaseException as problem:cleanup.append(repr(problem))
  self.sample();self.e['result']='PASS' if error is None and not cleanup else 'FAIL'
  if error:self.e['failure']=repr(error)
  if cleanup:self.e['cleanupFailures']=cleanup
  self.save()
  if cleanup:raise RuntimeError('Owned cleanup remains incomplete: '+repr(cleanup))
