#!/usr/bin/env python3
import base64,ctypes,fcntl,hashlib,json,os,secrets,shutil,signal,stat,subprocess,sys,time,uuid
from pathlib import Path

BASE=Path(sys.argv[2]);MODE=sys.argv[1]
assert os.getuid()==503 and BASE.is_dir() and not BASE.is_symlink() and stat.S_IMODE(BASE.stat().st_mode)==0o700
EXE=BASE/'bin/reachd';E=BASE/'evidence';LOG=BASE/'logs'
if len(sys.argv)>3:
 assert sys.argv[3].replace('-','').isalnum();LOG=LOG/sys.argv[3]
 LOG.mkdir(mode=0o700,exist_ok=False)
for name in ['evidence','logs','roots','controls','staging','secrets']:(BASE/name).mkdir(mode=0o700,exist_ok=True)
os.umask(0o077)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def read(path):return json.loads(Path(path).read_text())
def compact(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def boot():
 command=['/usr/sbin/sysctl','-n','kern.bootsessionuuid'];p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 out,err=p.communicate(timeout=15)
 record['processes'].append({'label':MODE+'-boot','command':command,'pid':p.pid,'joined':True,'exitCode':p.returncode,'stdoutSHA256':hashlib.sha256(out).hexdigest(),'stderrSHA256':hashlib.sha256(err).hexdigest()})
 save();assert p.returncode==0;return out.decode().strip().lower()
record=read(E/'campaign.json') if (E/'campaign.json').exists() else {'processes':[],'cells':[],'commandsChecked':0}
values=[p.read_bytes() for p in (BASE/'secrets').iterdir() if p.is_file()]
handles=[]
def save():write(E/'campaign.json',record)
def credential(name,value=None):
 value=value if value is not None else secrets.token_hex(32).encode();assert value not in values
 p=BASE/'secrets'/name
 with p.open('xb') as output:output.write(value)
 p.chmod(0o600);values.append(value);return p
def launch(label,args,secret=None,executable=EXE):
 assert not any(value in str(arg).encode() for value in values for arg in args)
 assert not any(value in item.encode() for value in values for item in os.environ.values())
 profile='(version 1)(allow default)(deny network*)'
 if MODE!='initialize':
  for role in ['host','client']:
   profile+=' (deny file-read-data (literal "'+str(BASE/'roots'/role/'bootstrap'/role/'current')+'"))'
 fd=os.open(secret,os.O_RDONLY|os.O_CLOEXEC) if secret is not None else None
 command=[str(executable),*map(str,args)]
 if fd is not None:command+=['--unlock-secret-fd',str(fd)]
 out=(LOG/(label+'.stdout')).open('xb');err=(LOG/(label+'.stderr')).open('xb')
 try:p=subprocess.Popen(command,stdout=out,stderr=err,pass_fds=() if fd is None else (fd,))
 finally:
  if fd is not None:os.close(fd)
 child={'label':label,'command':command,'pid':p.pid,'joined':False,'inheritedDescriptorCount':int(fd is not None),'inheritedSandboxProfile':profile,'logDirectory':str(LOG)}
 record['processes'].append(child);record['commandsChecked']+=1;save()
 handle=(p,child,out,err);handles.append(handle);return handle
def join(handle,expected=0):
 p,child,out,err=handle
 try:code=p.wait(timeout=90)
 except subprocess.TimeoutExpired:
  p.kill();code=p.wait();child['timedOut']=True
 child.update(exitCode=code,joined=True);out.close();err.close()
 child['stdoutSHA256']=sha(LOG/(child['label']+'.stdout'));child['stderrSHA256']=sha(LOG/(child['label']+'.stderr'));save()
 assert code==expected,(child['label'],code)
 assert max((LOG/(child['label']+s)).stat().st_size for s in ['.stdout','.stderr'])<=192<<20
 return child
def command(label,args,secret=None,expected=0,executable=EXE):return join(launch(label,args,secret,executable),expected)
def result(label):return read(LOG/(label+'.stdout'))
def last_result(label):return [json.loads(x) for x in (LOG/(label+'.stdout')).read_text().splitlines() if x.startswith('{')][-1]
def role_data(role):return read(E/(role+'.json'))
def retirement_args(role,digest=None,receipt=None):
 d=role_data(role)
 return ['durable-independent','retire-after-boot','--owner-receipt',receipt or d['receipt'],'--expected-digest',digest or d['digest']]
def unlocked(role):
 # Read status of only the exact selected existing container, with UI disabled.
 s=ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
 s.SecKeychainSetUserInteractionAllowed.argtypes=[ctypes.c_ubyte];s.SecKeychainSetUserInteractionAllowed.restype=ctypes.c_int32
 s.SecKeychainGetUserInteractionAllowed.argtypes=[ctypes.POINTER(ctypes.c_ubyte)];s.SecKeychainGetUserInteractionAllowed.restype=ctypes.c_int32
 s.SecKeychainOpen.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)];s.SecKeychainOpen.restype=ctypes.c_int32
 s.SecKeychainGetStatus.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)];s.SecKeychainGetStatus.restype=ctypes.c_int32
 assert s.SecKeychainSetUserInteractionAllowed(0)==0
 allowed=ctypes.c_ubyte(1);assert s.SecKeychainGetUserInteractionAllowed(ctypes.byref(allowed))==0 and allowed.value==0
 container=ctypes.c_void_p();assert s.SecKeychainOpen(role_data(role)['container'].encode(),ctypes.byref(container))==0
 state=ctypes.c_uint32();assert s.SecKeychainGetStatus(container,ctypes.byref(state))==0
 cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation');cf.CFRelease.argtypes=[ctypes.c_void_p];cf.CFRelease(container)
 result=bool(state.value&1)
 record.setdefault('statusObservations',[]).append({'role':role,'container':role_data(role)['container'],'unlocked':result,'securityUIDisabled':True});save()
 return result
def public(role):
 root=BASE/'roots'/role;control=BASE/'controls'/role
 return {str(p.relative_to(BASE)):sha(p) for p in [root/'bootstrap/intent.json',root/'bootstrap/ready.json',root/'agreement.json',root/role/'selection.json',control/'owner.json']}
def refuse(label,role,args=None,secret=None,expected=1,executable=EXE):
 before=public(role);phase=(BASE/'controls'/role/'owner.json.state.json').read_bytes()
 command(label,args or retirement_args(role),secret=secret,expected=expected,executable=executable)
 assert public(role)==before and (BASE/'controls'/role/'owner.json.state.json').read_bytes()==phase
 assert not (LOG/(label+'.stdout')).read_bytes()
def initialize():
 record['originalBoot']=boot();record['executableSHA256']=sha(EXE)
 assert not list((BASE/'roots').iterdir())
 # Fixture authoring precedes every original role. The production descriptor
 # binds Foundation's OS build string; host and cached guest builds can differ.
 command('fixture-os-version',['-l','JavaScript','-e','ObjC.import("Foundation"); $.NSProcessInfo.processInfo.operatingSystemVersionString.js'],executable=Path('/usr/bin/osascript'))
 observed=(LOG/'fixture-os-version.stdout').read_text().strip()
 assert observed.startswith('Version ') and '(Build ' in observed and '\n' not in observed
 modelPath=BASE/'public-model.json';before=read(modelPath);model=json.loads(json.dumps(before))
 model['descriptor']['backend']='arm64-little-endian;cpu;'+observed
 prior=sha(modelPath);modelPath.write_bytes(compact(model));modelPath.chmod(0o600)
 originalBackend=before['descriptor']['backend'];before['descriptor']['backend']=model['descriptor']['backend'];assert before==model
 record['fixtureAuthoring']={'hostPublicModelSHA256':prior,'guestPublicModelSHA256':sha(modelPath),'originalHostBackend':originalBackend,'actualGuestBackend':model['descriptor']['backend'],'onlyBackendFieldSelectedForGuest':True,'beforeOriginalRoleInitialization':True}
 save()
 command('provision',['durable-independent','provision','--public-model',BASE/'public-model.json','--output',BASE/'staging/pair','--port','54194','--retention-seconds','30'])
 for role in ['host','client']:
  control=BASE/'controls'/role;control.mkdir(mode=0o700)
  own=credential(role+'-input');credential(role+'-wrong')
  root=BASE/'roots'/role;receipt=control/'owner.json'
  args=['durable-independent','init','--finish','--owner-receipt',receipt,'--role',role,'--root',root,'--provisioned',BASE/'staging/pair'/role]
  if role=='host':args+=['--model',BASE/'model']
  child=command(role+'-init',args,secret=own);ready=last_result(role+'-init');core=read(root/'bootstrap/ready.json')['core'];info=root.stat()
  assert core['version']==3 and core['unlockPolicy']=='caller-supplied-v1' and core['boot']==record['originalBoot']
  write(E/(role+'.json'),{'role':role,'root':str(root),'receipt':str(receipt),'digest':ready['ownerReceiptDigest'],'container':core['container'],'core':core,'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'initializerPID':child['pid'],'public':public(role)})
  refuse(role+'-same-boot',role,secret=own)
 shutil.rmtree(BASE/'staging/pair')
 assert all(x['joined'] for x in record['processes'])
 record['initializersJoined']=True;record['provisioningRemoved']=True;save()
 print('ORIGINAL_V3_ROLES_READY',flush=True)
def postboot():
 if 'failure' in record:record.setdefault('failedAttempts',[]).append(record.pop('failure'))
 currentBoot=boot();assert currentBoot!=record['originalBoot'] and sha(EXE)==record['executableSHA256']
 record.setdefault('postbootObservations',[]).append(currentBoot)
 record['currentBoot']=currentBoot;record['bootChanged']=True;record['currentRoots']={}
 metadataBefore=[]
 for kind,args in [('default',['default-keychain','-d','user']),('search',['list-keychains','-d','user'])]:
  command('metadata-before-'+kind,args,executable=Path('/usr/bin/security'));metadataBefore.append((LOG/('metadata-before-'+kind+'.stdout')).read_bytes())
 for role in ['host','client']:
  d=role_data(role);root=Path(d['root']);info=root.stat();assert info.st_ino==d['inode'] and info.st_uid==d['uid']==503 and stat.S_IMODE(info.st_mode)==d['mode']==0o700
  assert public(role)==d['public']
  record['currentRoots'][role]={'device':info.st_dev,'inode':info.st_ino,'originalDevice':d['device'],'originalPublicBytesExact':True}
  payload=root/'bootstrap'/role/'current';payload.write_bytes(b'undecodable prior-boot generation payload');payload.chmod(0o600)
  assert not unlocked(role),'expected original container locked after actual reboot'
  rootCommand='host' if role=='host' else 'recover'
  args=['durable-independent',rootCommand,'--root',root,'--report',E/(role+'-forbidden-report.json')]
  refuse(role+'-ordinary-refused',role,args=args)
  assert not (E/(role+'-forbidden-report.json')).exists()
  refuse(role+'-ordinary-unlock-refused',role,args=['durable-independent','unlock','--owner-receipt',d['receipt'],'--expected-digest',d['digest']],secret=BASE/'secrets'/(role+'-input'))
  refuse(role+'-ordinary-retire-refused',role,args=['durable-independent','retire','--owner-receipt',d['receipt'],'--expected-digest',d['digest']])
  assert not unlocked(role)
 record['cells'].append({'case':'prior-boot-refusal','ordinaryAcquisitionUnlockRetirementRefused':True,'noReportPublished':True,'generationPayloadsUndecodableAndReadDenied':True});save()
 own=BASE/'secrets/host-input';wrong=BASE/'secrets/host-wrong'
 refuse('wrong-digest','host',args=retirement_args('host',digest='0'*64),secret=own)
 refuse('missing-fd','host');refuse('standard-fd','host',args=retirement_args('host')+['--unlock-secret-fd','0'])
 malformed=credential('malformed',b'A'*63+b'\n');refuse('malformed-fd','host',secret=malformed)
 refuse('wrong-input','host',secret=wrong);assert not unlocked('host')
 for suffix in ['.lock']:
  with Path(role_data('host')['receipt']+suffix).open('rb') as held:
   fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);refuse('active-lifetime','host',secret=own)
 with (BASE/'roots/host/bootstrap/host/lock').open('rb') as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);refuse('active-journal','host',secret=own)
 root=BASE/'roots/host';moved=BASE/'roots/host-original';root.rename(moved)
 try:
  root.mkdir(mode=0o700);(root/'sentinel').write_bytes(b'untouched')
  command('replacement-root',retirement_args('host'),secret=own,expected=1);assert (root/'sentinel').read_bytes()==b'untouched'
  shutil.rmtree(root);root.symlink_to(moved,target_is_directory=True)
  command('symlink-root',retirement_args('host'),secret=own,expected=1);assert root.is_symlink();root.unlink()
 finally:
  if root.is_symlink():root.unlink()
  if root.exists():shutil.rmtree(root)
  moved.rename(root)
 copied=BASE/'bin/wrong-reachd';shutil.copyfile(EXE,copied);copied.chmod(0o700)
 try:refuse('wrong-executable','host',secret=own,executable=copied)
 finally:copied.unlink()
 receipt=Path(role_data('host')['receipt']);saved=receipt.read_bytes()
 try:
  value=json.loads(saved);value['ready']['core']['unlockPolicy']='unselected';receipt.write_bytes(compact(value))
  refuse('wrong-policy','host',secret=own)
 finally:receipt.write_bytes(saved)
 selection=root/'host/selection.json';saved=selection.read_bytes()
 try:
  selection.write_bytes(b'invalid selected public record');refuse('wrong-selection','host',secret=own)
 finally:selection.write_bytes(saved)
 assert not unlocked('host') and public('host')==role_data('host')['public']
 paths=[root/'bootstrap/ready.json',receipt,Path(str(receipt)+'.state.json')];saved=[p.read_bytes() for p in paths]
 try:
  ready,ownership,phase=map(json.loads,saved);ready['confirmations']=[base64.b64encode(bytes(32)).decode()]*len(ready['confirmations'])
  ownership['ready']=ready;ownership['container']['confirmations']=ready['confirmations']
  expected=hashlib.sha256(b'S96/role-ownership-receipt/v1\0'+compact(ownership)).hexdigest();phase['receipt']=expected
  for path,value in zip(paths,[ready,ownership,phase]):path.write_bytes(compact(value))
  refuse('original-key-refused','host',args=retirement_args('host',digest=expected),secret=own)
  assert 'refused-locked' in (LOG/'original-key-refused.stderr').read_text() and not unlocked('host')
  assert not Path(str(receipt)+'.cleanup.json').exists()
 finally:
  for path,value in zip(paths,saved):path.write_bytes(value)
 record['cells'].append({'case':'guards','wrongOwnershipInputSelectionExecutableFDRefused':True,'lifetimeAndJournalExclusion':True,'originalKeyRefusalRelocked':True,'originalPublicBytesRestored':True});save()
 # Keep the observable post-delete boundary open long enough for a real SIGSTOP.
 padding=root/'bootstrap/host/retirement-padding';padding.mkdir(mode=0o700)
 for index in range(4096):(padding/str(index)).write_bytes(b'x')
 handle=launch('host-retire-cut',retirement_args('host')+['--progress'],secret=own);p=handle[0]
 deadline=time.monotonic()+60;cut=False
 while time.monotonic()<deadline:
  if '"keychain-deleted"' in (LOG/'host-retire-cut.stdout').read_text():
   p.send_signal(signal.SIGSTOP);cut=True;break
  if p.poll() is not None:break
  time.sleep(0.001)
 assert cut and root.exists() and not Path(role_data('host')['container']).exists(),'post-delete observation raced root removal'
 observation=Path(str(receipt)+'.cleanup.json');state=Path(str(receipt)+'.state.json')
 assert read(state)['phase']=='retiring';obs=read(observation);info=root.stat()
 assert obs['boot']==currentBoot and obs['device']==info.st_dev and obs['inode']==info.st_ino and obs['root']==str(root)
 p.kill();join(handle,expected=-9);assert public('host')==role_data('host')['public']
 record['cells'].append({'case':'actual-post-delete-cut','pid':p.pid,'joined':True,'exitCode':-9,'rootPresentContainerAbsent':True,'observation':obs});save()
 original=observation.read_bytes();observation.unlink()
 try:refuse('retry-missing-observation','host')
 finally:observation.write_bytes(original);observation.chmod(0o600)
 for label,changes in [('malformed',None),('another-boot',{'boot':str(uuid.uuid4())}),('wrong-tuple',{'device':obs['device']^1})]:
  try:
   value=dict(obs)
   if changes:value.update(changes)
   observation.write_bytes(b'invalid' if changes is None else compact(value))
   refuse('retry-'+label,'host')
  finally:observation.write_bytes(original)
 command('host-fresh-retry',retirement_args('host'))
 assert result('host-fresh-retry')['stage']=='retired'
 command('client-retire',retirement_args('client'),secret=BASE/'secrets/client-input')
 assert result('client-retire')['stage']=='retired'
 for role in ['host','client']:
  d=role_data(role);assert not Path(d['root']).exists() and not Path(d['container']).exists()
  assert read(d['receipt']+'.state.json')['phase']=='retired'
  assert sha(d['receipt'])==d['public'][str(Path(d['receipt']).relative_to(BASE))]
  command(role+'-absence',retirement_args(role));assert result(role+'-absence')['stage']=='absent'
 assert all(x['joined'] for x in record['processes'])
 for index,(kind,args) in enumerate([('default',['default-keychain','-d','user']),('search',['list-keychains','-d','user'])]):
  command('metadata-after-'+kind,args,executable=Path('/usr/bin/security'))
  assert (LOG/('metadata-after-'+kind+'.stdout')).read_bytes()==metadataBefore[index]
 record['unrelatedDefaultAndSearchListUnchanged']=True
 record['cells'].append({'case':'retired','bothOriginalRolesRetired':True,'freshSameObservedBootRetry':True,'missingMalformedDifferentBootAndTupleRefused':True,'repeatedAbsenceOnly':True});record['result']='PASS';save()
 print('POSTBOOT_RETIREMENT_AND_RETRY_PASS',flush=True)
def scan():
 corpus=(BASE/'recorded-evidence.txt').read_bytes()
 paths=[p for folder in ['logs','evidence','controls'] for p in (BASE/folder).rglob('*') if p.is_file()]
 matches=sum(value in corpus for value in values)+sum(value in p.read_bytes() for value in values for p in paths)
 assert matches==0 and not any(value in x.encode() for value in values for x in sys.argv+list(os.environ.values()))
 report={'fixtureInputs':len(values),'filesChecked':len(paths),'hostEvidenceBytes':len(corpus),'contentMatches':0,'commandEnvironmentMatches':0,'commandEnvironmentChecks':record['commandsChecked'],'credentialHashesRecorded':False}
 write(E/'secret-absence.json',report)
 shutil.rmtree(BASE/'secrets');(BASE/'recorded-evidence.txt').unlink()
 assert not list((BASE/'roots').iterdir()) and not list((BASE/'staging').iterdir())
 record['callerInputsRemoved']=True;save();print(json.dumps(report,sort_keys=True),flush=True)
try:
 if MODE=='initialize':initialize()
 elif MODE=='postboot':postboot()
 elif MODE=='scan':scan()
 else:raise ValueError('unknown guest phase')
except BaseException as error:
 for handle in handles:
  if not handle[1]['joined']:
   if handle[0].poll() is None:handle[0].kill()
   join(handle,expected=handle[0].wait())
 record['failure']={'mode':MODE,'type':type(error).__name__,'message':str(error)};save();raise
