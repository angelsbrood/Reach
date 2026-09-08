#!/usr/bin/env python3
import sys
sys.dont_write_bytecode=True
from common import Campaign,parser
from pathlib import Path
import base64,fcntl,hashlib,json,os,shutil,stat

args=parser('Qualify S96 selected ownership, locked refusal and fresh retirement retry on owned fixtures.').parse_args()
c=Campaign(args);problem=None
def compact(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def receipt_digest(value):return hashlib.sha256(b'S96/role-ownership-receipt/v1\0'+compact(value)).hexdigest()
def state(role):return Path(str(role['receipt'])+'.state.json')
def refusal(label,role,expected=None):
 child=c.command(label,['durable-independent','retire','--owner-receipt',role['receipt'],'--expected-digest',expected or role['digest'],'--progress'],expected=1,denied=role['denied'])
 assert role['root'].exists() and Path(role['ready']['core']['container']).exists()
 assert json.loads(state(role).read_text())['phase']=='ready'
 assert '"stage":"retiring"' not in (c.run/'logs'/(label+'.stdout')).read_text()
 return child
def metadata(label):
 result={}
 for command in ['default-keychain','list-keychains']:
  c.command(label+'-'+command,[command,'-d','user'],program='/usr/bin/security',network=False)
  result[command]=(c.run/'logs'/(label+'-'+command+'.stdout')).read_text()+(c.run/'logs'/(label+'-'+command+'.stderr')).read_text()
 return result
def dispose_locked_fixture(role):
 identity=role['ready']['core']['lifecycle']['identity'];s=role['root'].lstat()
 assert s.st_dev==identity['device'] and s.st_ino==identity['inode'] and stat.S_ISDIR(s.st_mode)
 container=Path(role['ready']['core']['container']);assert container==role['root']/'keys/role.keychain-db'
 before=metadata('locked-before-disposal')
 c.command('locked-exact-fixture-delete',['delete-keychain',container],program='/usr/bin/security',network=False)
 assert not container.exists()
 after=metadata('locked-after-disposal')
 assert before['default-keychain']==after['default-keychain']
 def unrelated(value):return [line for line in value.splitlines() if str(container) not in line]
 assert unrelated(before['list-keychains'])==unrelated(after['list-keychains'])
 shutil.rmtree(role['root']);role['fixtureDisposed']=True
 c.e['cells'].append({'case':'locked-container','freshReadRefused':True,'retireBeforeAuthorizationRefused':True,'noUnlockOrPassword':True,'disposal':'exact owned negative-fixture authority; not product retirement','unrelatedMetadataPreserved':True})
try:
 roles,_=c.initialize('guards',roles=('client',));role=roles['client']
 refusal('wrong-digest',role,expected='0'*64)
 root=role['root'];original=root.with_name(root.name+'-original')
 root.rename(original)
 try:
  root.mkdir(mode=0o700);(root/'replacement').write_text('untouched');(root/'replacement').chmod(0o600)
  c.command('replacement-root',['durable-independent','retire','--owner-receipt',role['receipt'],'--expected-digest',role['digest']],expected=1,denied=role['denied'])
  assert (root/'replacement').read_text()=='untouched';shutil.rmtree(root)
  root.symlink_to(original,target_is_directory=True)
  c.command('symlink-root',['durable-independent','retire','--owner-receipt',role['receipt'],'--expected-digest',role['digest']],expected=1,denied=role['denied'])
  assert root.is_symlink();root.unlink()
 finally:
  if root.is_symlink():root.unlink()
  if root.exists():shutil.rmtree(root)
  original.rename(root)
 lock=Path(str(role['receipt'])+'.lock')
 with lock.open('rb') as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
  refusal('active-lease-retire',role)
  c.command('active-lease-worker',['durable-independent','recover','--root',root],expected=1,denied=role['denied'])
  assert 'BootstrapError' in (c.run/'logs/active-lease-worker.stderr').read_text()
 # Alter only public owned records, never key material. A newly claimed digest
 # must still fail original-key confirmation before the retiring transition.
 paths=[root/'bootstrap/ready.json',role['receipt'],state(role)]
 saved=[p.read_bytes() for p in paths]
 try:
  ready=json.loads(saved[0]);ownership=json.loads(saved[1]);progress=json.loads(saved[2])
  zero=base64.b64encode(bytes(32)).decode();ready['confirmations']=[zero]*len(ready['confirmations'])
  ownership['ready']=ready;ownership['container']['confirmations']=ready['confirmations']
  forged=receipt_digest(ownership);progress['receipt']=forged
  for p,value in zip(paths,[ready,ownership,progress]):p.write_bytes(compact(value))
  refusal('original-key-confirmation',role,expected=forged)
 finally:
  for p,value in zip(paths,saved):p.write_bytes(value)
 assert receipt_digest(json.loads(role['receipt'].read_text()))==role['digest']
 c.retire('guards-retire',role)
 c.e['cells'].append({'case':'selected-ownership','wrongDigest':True,'replacementAndSymlinkRefused':True,'activeLeaseBeforeWorkerKeys':True,'originalKeyConfirmationBeforeTransition':True,'freshRetire':True})

 roles,_=c.initialize('boundary',roles=('client',));role=roles['client']
 # Opaque owned journal padding makes the content-free removal boundary
 # observable. It is never read as a manifest/snapshot or used for generation.
 padding=role['root']/'bootstrap/client/opaque-cleanup-fixture';padding.mkdir(mode=0o700)
 for i in range(1024):
  p=padding/str(i);p.write_bytes(b'owned cleanup fixture');p.chmod(0o600)
 retirement=c.child('boundary-first-retire',['durable-independent','retire','--owner-receipt',role['receipt'],'--expected-digest',role['digest'],'--progress'],denied=role['denied'])
 event=retirement.until(lambda v:v.get('stage')=='keychain-deleted',30);assert event
 retirement.pause()
 assert role['root'].exists() and not Path(role['ready']['core']['container']).exists(),'retirement boundary raced full removal'
 assert json.loads(state(role).read_text())['phase']=='retiring'
 assert retirement.kill()==-9
 c.command('retiring-worker-refused',['durable-independent','recover','--root',role['root']],expected=1,denied=role['denied'])
 retry=c.retire('boundary-fresh-retry',role)
 assert retry.p.pid!=retirement.p.pid and retirement.joined and retry.joined
 c.e['cells'].append({'case':'after-keychain-deletion','originalRetirePID':retirement.p.pid,'retryPID':retry.p.pid,'bothJoined':True,'rootPresentAndContainerAbsentAtCut':True,'newAcquisitionRefused':True,'freshRetryCompleted':True,'opaquePaddingFiles':1024})

 roles,_=c.initialize('locked',roles=('client',));role=roles['client']
 c.command('lock-owned-fixture',['lock-keychain',role['ready']['core']['container']],program='/usr/bin/security',network=False)
 c.command('locked-fresh-worker',['durable-independent','recover','--root',role['root']],expected=1,denied=role['denied'])
 assert 'RootKeyError' in (c.run/'logs/locked-fresh-worker.stderr').read_text()
 refusal('locked-fresh-retire',role)
 dispose_locked_fixture(role)
 c.sample()
except BaseException as error:
 problem=error;raise
finally:c.finish(problem)
