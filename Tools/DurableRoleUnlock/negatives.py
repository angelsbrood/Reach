#!/usr/bin/env python3
import sys
sys.dont_write_bytecode=True
from support import Campaign,parser
from pathlib import Path
import base64,fcntl,hashlib,json,os,shutil

p=parser('Qualify selected unlock refusals, original-key relock and authenticated retiring phase.')
p.add_argument('--case',choices=['all','guards','retiring','legacy'],default='all')
args=p.parse_args();c=Campaign(args);problem=None
def compact(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def state(role):return Path(str(role['receipt'])+'.state.json')
try:
 if args.case in ['all','guards']:
  roles,_=c.initialize('guards',roles=('client',));role=roles['client'];root=role['root']
  c.lock('guards-lock',role)
  c.unlock('wrong-digest',role,expected=1,digest='0'*64)
  assert c.status('wrong-digest-still-locked',role) is False
  c.command('missing-fd',['durable-independent','unlock','--owner-receipt',role['receipt'],'--expected-digest',role['digest']],expected=64,denied=role['denied'])
  c.command('standard-fd',['durable-independent','unlock','--owner-receipt',role['receipt'],'--expected-digest',role['digest'],'--unlock-secret-fd',0],expected=1,denied=role['denied'])
  role['secret'].chmod(0o644)
  try:c.unlock('nonprivate-fd',role,expected=1)
  finally:role['secret'].chmod(0o600)
  fd=os.open(role['secret'],os.O_RDWR|os.O_CLOEXEC)
  try:bad=c.child('write-access-fd',['durable-independent','unlock','--owner-receipt',role['receipt'],'--expected-digest',role['digest'],'--unlock-secret-fd',fd],descriptors=(fd,),denied=role['denied'])
  finally:os.close(fd)
  assert bad.join()==1
  assert c.status('bad-fds-still-locked',role) is False

  original=root.with_name(root.name+'-original');root.rename(original)
  try:
   root.mkdir(mode=0o700);(root/'replacement').write_text('untouched');(root/'replacement').chmod(0o600)
   c.unlock('replacement-root',role,expected=1);assert (root/'replacement').read_text()=='untouched'
   shutil.rmtree(root);root.symlink_to(original,target_is_directory=True)
   c.unlock('symlink-root',role,expected=1);assert root.is_symlink();root.unlink()
  finally:
   if root.is_symlink():root.unlink()
   if root.exists():shutil.rmtree(root)
   original.rename(root)
  assert c.status('root-selection-still-locked',role) is False
  with Path(str(role['receipt'])+'.lock').open('rb') as held:
   fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
   c.unlock('active-lease',role,expected=1)
   assert 'BootstrapError' in (c.run/'logs/active-lease.stderr').read_text()
  assert c.status('active-lease-still-locked',role) is False
  saved=role['receipt'].read_bytes()
  try:
   receipt=json.loads(saved);receipt['ready']['core']['unlockPolicy']='unselected-policy'
   role['receipt'].write_bytes(compact(receipt));c.unlock('wrong-policy',role,expected=1)
  finally:role['receipt'].write_bytes(saved)
  assert c.status('wrong-policy-still-locked',role) is False

  # Only bounded public fixture confirmations are changed. Original protected
  # keys and the caller input remain exact; post-unlock verification must relock.
  paths=[root/'bootstrap/ready.json',role['receipt'],state(role)];saved=[p.read_bytes() for p in paths]
  try:
   ready,ownership,progress=map(json.loads,saved)
   zero=base64.b64encode(bytes(32)).decode();ready['confirmations']=[zero]*len(ready['confirmations'])
   ownership['ready']=ready;ownership['container']['confirmations']=ready['confirmations']
   expected=hashlib.sha256(b'S96/role-ownership-receipt/v1\0'+compact(ownership)).hexdigest();progress['receipt']=expected
   for path,value in zip(paths,[ready,ownership,progress]):path.write_bytes(compact(value))
   c.unlock('original-key-failure',role,expected=1,digest=expected)
   assert 'verification-refused-locked' in (c.run/'logs/original-key-failure.stderr').read_text()
   assert c.status('original-key-failure-relocked',role) is False
  finally:
   for path,value in zip(paths,saved):path.write_bytes(value)
  assert c.unlock('guards-correct-unlock',role)['stage']=='unlocked'
  assert c.unlock('already-unlocked-wrong-input',role,wrong=True)['stage']=='already-unlocked'
  c.retire('guards-retire',role)

  # A real regular private descriptor with malformed bytes must be rejected
  # before Keychain creation; ordinary root/control construction is rolled back.
  staging=c.run/'staging/bad-input';badroot=c.run/'roots/bad-input-client';control=c.run/'controls/bad-input-client';control.mkdir(mode=0o700)
  badfile=c.run/'secrets/bad-input';badbytes=b'A'*63+b'\n';badfile.write_bytes(badbytes);badfile.chmod(0o600);c.secretValues.append(badbytes)
  c.command('bad-input-provision',['durable-independent','provision','--public-model',args.public_model,'--output',staging,'--port',c.port()])
  c.with_descriptor('malformed-init',['durable-independent','init','--finish','--owner-receipt',control/'owner.json','--role','client','--root',badroot,'--provisioned',staging/'client'],badfile,expected=1)
  assert not badroot.exists() and not list(control.iterdir());shutil.rmtree(staging)
  c.e['cells'].append({'case':'guards','wrongOwnershipPolicyAndActiveLeaseBeforeUnlock':True,'descriptorCLIRefusals':True,'originalKeyFailureAfterOSUnlockRelocked':True,'restoredOriginalPublicFixtureRecords':True,'alreadyUnlockedIsAvailabilityOnly':True,'malformedInitializerRemovedOwnRootAndControls':True})

 if args.case in ['all','legacy']:
  roles,_=c.initialize('legacy',roles=('client',),unlock=False);role=roles['client']
  role['secret']=c.secret(c.run/'secrets/legacy-client','unsupported-input')
  assert c.status('legacy-initial-state',role) is True
  c.unlock('legacy-policy-refused',role,expected=1)
  assert c.status('legacy-final-state',role) is True
  c.retire('legacy-retire',role)
  c.e['cells'].append({'case':'legacy-v2','noUnlockPolicyAdded':True,'explicitUnlockRefused':True,'originalV2RetirementPassed':True})

 if args.case in ['all','retiring']:
  roles,_=c.initialize('retiring',roles=('client',));role=roles['client']
  retiring=c.child('authorize-retiring',['durable-independent','retire','--owner-receipt',role['receipt'],'--expected-digest',role['digest'],'--progress'],denied=role['denied'])
  assert retiring.until(lambda v:v.get('stage')=='retiring',30)
  retiring.pause()
  assert role['root'].exists() and Path(role['ready']['core']['container']).exists(),'retiring observation raced container deletion'
  assert json.loads(state(role).read_text())['phase']=='retiring'
  assert retiring.kill()==-9
  c.lock('retiring-lock',role)
  c.worker_refusal('retiring-locked-worker',role)
  result=c.unlock('retiring-fresh-unlock',role)
  assert result['stage']=='unlocked' and result['phase']=='retiring'
  c.worker_refusal('retiring-unlocked-worker',role)
  assert json.loads(state(role).read_text())['phase']=='retiring'
  c.retire('retiring-complete',role)
  c.e['cells'].append({'case':'authenticated-retiring','authorizingRetirePID':retiring.p.pid,'authorizingRetireJoined':True,'originalContainerPresentAtCut':True,'freshUnlockPreservedRetiring':True,'newWorkersRefusedBeforeAndAfterUnlock':True,'freshRetirementCompleted':True})
 c.sample()
except BaseException as error:
 problem=error;raise
finally:c.finish(problem)
