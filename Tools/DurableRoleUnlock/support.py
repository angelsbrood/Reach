from pathlib import Path
import importlib.util,json,os,secrets,shutil,stat,sys

spec=importlib.util.spec_from_file_location('s96_lifecycle',Path(__file__).resolve().parents[1]/'DurableRoleLifecycle/common.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
parser=legacy.parser

STATUS_SCRIPT='''import ctypes as c,json,sys
s=c.CDLL('/System/Library/Frameworks/Security.framework/Security')
s.SecKeychainSetUserInteractionAllowed.argtypes=[c.c_ubyte];s.SecKeychainSetUserInteractionAllowed.restype=c.c_int32
s.SecKeychainOpen.argtypes=[c.c_char_p,c.POINTER(c.c_void_p)];s.SecKeychainOpen.restype=c.c_int32
s.SecKeychainGetStatus.argtypes=[c.c_void_p,c.POINTER(c.c_uint32)];s.SecKeychainGetStatus.restype=c.c_int32
assert s.SecKeychainSetUserInteractionAllowed(0)==0
s.SecKeychainGetUserInteractionAllowed.argtypes=[c.POINTER(c.c_ubyte)];s.SecKeychainGetUserInteractionAllowed.restype=c.c_int32
allowed=c.c_ubyte(1);assert s.SecKeychainGetUserInteractionAllowed(c.byref(allowed))==0 and allowed.value==0
k=c.c_void_p();assert s.SecKeychainOpen(sys.argv[1].encode(),c.byref(k))==0
v=c.c_uint32();assert s.SecKeychainGetStatus(k,c.byref(v))==0
print(json.dumps({'unlocked':bool(v.value&1)}))
'''

class Campaign(legacy.Campaign):
 def __init__(self,args):
  self.args=args;self.base=args.scratch.resolve(strict=True)
  assert str(self.base).startswith('/private/tmp/reach-s97.') and stat.S_IMODE(self.base.stat().st_mode)==0o700 and self.base.stat().st_uid==os.getuid()
  assert args.label and all(v.islower() or v.isdigit() or v=='-' for v in args.label)
  self.run=self.base/('qualification-'+args.label);self.run.mkdir(mode=0o700)
  for name in ['bin','logs','reports','roots','controls','staging','secrets']:(self.run/name).mkdir(mode=0o700)
  self.exe=self.run/'bin/reachd';shutil.copyfile(args.executable,self.exe);self.exe.chmod(0o700)
  shutil.copyfile(args.metallib,self.run/'bin/mlx.metallib')
  self.children=[];self.roles=[];self.secretValues=[];self.environmentChecks=0
  self.e={'executable':str(self.exe),'sha256':legacy.digest(self.exe),'metalSHA256':legacy.digest(args.metallib),'processes':[],'cells':[]}
  self.sample();self.save()
 def secret(self,folder,name):
  folder.mkdir(mode=0o700,exist_ok=True);path=folder/name
  value=secrets.token_hex(32).encode();assert value not in self.secretValues
  with path.open('xb') as output:output.write(value)
  path.chmod(0o600);self.secretValues.append(value);return path
 def child(self,label,arguments,**kwargs):
  encoded=[str(v).encode() for v in arguments]
  assert not any(secret in arg for secret in self.secretValues for arg in encoded)
  assert not any(secret in value.encode() for secret in self.secretValues for value in os.environ.values())
  self.environmentChecks+=1
  child=legacy.Child(self,label,arguments,**kwargs)
  child.record['inheritedDescriptorCount']=len(kwargs.get('descriptors',()))
  self.save();return child
 def with_descriptor(self,label,arguments,path,expected=0,**kwargs):
  fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
  try:child=self.child(label,[*arguments,'--unlock-secret-fd',fd],descriptors=(fd,),**kwargs)
  finally:os.close(fd)
  assert child.join()==expected,(label,child.record.get('exit_code'))
  return child
 def initialize(self,label,roles=('host','client'),retention=86400,unlock=True):
  port=self.port();staging=self.run/'staging'/label
  self.command(label+'-provision',['durable-independent','provision','--public-model',self.args.public_model,'--output',staging,'--port',port,'--retention-seconds',retention])
  selected={}
  for role in roles:
   root=self.run/'roots'/(label+'-'+role);control=self.run/'controls'/(label+'-'+role);control.mkdir(mode=0o700)
   ownSecret=self.run/'secrets'/(label+'-'+role);ownSecret.mkdir(mode=0o700)
   secret=self.secret(ownSecret,'input') if unlock else None
   wrong=self.secret(ownSecret,'wrong') if unlock else None
   peer='client' if role=='host' else 'host'
   denied=[self.run/'roots'/(label+'-'+peer),self.run/'controls'/(label+'-'+peer),self.run/'secrets'/(label+'-'+peer)]
   receipt=control/'owner.json'
   arguments=['durable-independent','init','--finish','--owner-receipt',receipt,'--role',role,'--root',root,'--provisioned',staging/role]
   if role=='host':arguments+=['--model',self.args.model]
   creator=self.with_descriptor(label+'-'+role+'-init',arguments,secret,denied=denied) if unlock else self.command(label+'-'+role+'-init',arguments,denied=denied)
   rows=[json.loads(line) for line in (self.run/'logs'/(creator.label+'.stdout')).read_text().splitlines() if line.startswith('{')]
   greeting=next(v for v in rows if v.get('stage')=='ready');expected=greeting['ownerReceiptDigest']
   ready=json.loads((root/'bootstrap/ready.json').read_text());ownership=json.loads(receipt.read_text())
   assert ready['core']['version']==(3 if unlock else 2) and ownership['ready']==ready
   assert ready['core'].get('unlockPolicy')==('caller-supplied-v1' if unlock else None)
   assert creator.joined and creator.p.returncode==0 and stat.S_IMODE(receipt.stat().st_mode)==0o600
   item={'role':role,'root':root,'control':control,'receipt':receipt,'digest':expected,'ready':ready,'greeting':greeting,'denied':denied,'initializerPID':creator.p.pid,'retired':False,'secret':secret,'wrong':wrong}
   self.roles.append(item);selected[role]=item
  shutil.rmtree(staging);assert not staging.exists()
  self.e.setdefault('provisioningRemoved',[]).append(str(staging));self.save()
  (self.run/'reports'/(label+'-roles.json')).write_text(json.dumps({k:{'ready':v['ready'],'greeting':v['greeting'],'initializerPID':v['initializerPID']} for k,v in selected.items()},sort_keys=True,indent=2)+'\n')
  return selected,port
 def status(self,label,role):
  child=self.command(label,['-c',STATUS_SCRIPT,role['ready']['core']['container']],program='/usr/bin/python3',network=False,denied=role['denied'])
  return json.loads((self.run/'logs'/(label+'.stdout')).read_text())['unlocked']
 def lock(self,label,role):
  self.command(label,['lock-keychain',role['ready']['core']['container']],program='/usr/bin/security',network=False,denied=role['denied'])
  assert self.status(label+'-state',role) is False
 def worker_refusal(self,label,role):
  command='host' if role['role']=='host' else 'recover'
  self.command(label,['durable-independent',command,'--root',role['root'],'--report',self.run/'reports'/(label+'.json')],expected=1,denied=role['denied'])
  assert not (self.run/'reports'/(label+'.json')).exists()
 def unlock(self,label,role,expected=0,wrong=False,digest=None,receipt=None):
  statePath=Path(str(role['receipt'])+'.state.json');beforeState=statePath.read_bytes()
  child=self.with_descriptor(label,['durable-independent','unlock','--owner-receipt',receipt or role['receipt'],'--expected-digest',digest or role['digest']],role['wrong'] if wrong else role['secret'],expected=expected,denied=role['denied'])
  assert statePath.read_bytes()==beforeState
  if expected==0:
   assert json.loads((role['root']/'bootstrap/ready.json').read_text())==role['ready']
   result=json.loads((self.run/'logs'/(label+'.stdout')).read_text())
   assert result['bootstrap']==role['ready']['core']['identifier'] and result['receiptDigest']==role['digest']
   return result
  assert not (self.run/'logs'/(label+'.stdout')).read_bytes()
  return None
 def secret_absence(self):
  paths=[self.run/'evidence.json',*[p for name in ['logs','reports','controls'] for p in (self.run/name).rglob('*') if p.is_file()]]
  paths += [p for directory in [self.base/'logs',self.base/'evidence'] for p in directory.rglob('*') if p.is_file()]
  count=0
  for path in dict.fromkeys(paths):
   value=path.read_bytes();count+=sum(secret in value for secret in self.secretValues)
  assert count==0
  return {'fixtureSecrets':len(self.secretValues),'filesChecked':len(paths),'contentMatches':count,'commandEnvironmentChecks':self.environmentChecks,'commandEnvironmentMatches':0,'secretHashesRecorded':False}
 def finish(self,error=None):
  cleanup=[]
  for child in self.children:
   if not child.joined:
    try:child.stop()
    except BaseException as problem:cleanup.append(type(problem).__name__);child.kill()
  for role in reversed(self.roles):
   if not role['retired']:
    try:
     if Path(role['ready']['core']['container']).exists() and role['secret'] is not None and role['ready']['core']['version']==3:self.unlock('cleanup-unlock-'+role['root'].name,role)
     self.retire('cleanup-retire-'+role['root'].name,role)
    except BaseException as problem:cleanup.append(type(problem).__name__)
  if list((self.run/'roots').iterdir()):cleanup.append('owned root remains')
  self.e['secretAbsence']=self.secret_absence()
  if not cleanup:
   shutil.rmtree(self.run/'secrets');self.e['callerSecretFixturesRemoved']=True
  self.sample();self.e['result']='PASS' if error is None and not cleanup else 'FAIL'
  if error:self.e['failure']=type(error).__name__
  if cleanup:self.e['cleanupFailures']=cleanup
  self.save()
  if cleanup:raise RuntimeError('Owned cleanup incomplete; preserve frozen executable and caller fixtures.')
