#!/usr/bin/env python3
import sys
sys.dont_write_bytecode=True
from support import Campaign,parser
from pathlib import Path
import json,subprocess,time

p=parser('Qualify explicit descriptor-based unlock and original ordinary recovery on owned loopback.')
p.add_argument('--mode',choices=['smoke','reference','recovery'],required=True)
p.add_argument('--reference',type=Path)
args=p.parse_args()
assert args.mode!='recovery' or args.reference is not None
c=Campaign(args);problem=None
try:
 roles,port=c.initialize('ordinary',roles=('client',) if args.mode=='smoke' else ('host','client'),retention=30 if args.mode=='recovery' else 86400)
 if args.mode=='smoke':
  role=roles['client'];c.lock('client-lock',role);c.worker_refusal('locked-worker',role)
  c.unlock('wrong-unlock',role,wrong=True,expected=1);assert c.status('still-locked',role) is False
  assert c.unlock('correct-unlock',role)['stage']=='unlocked'
  assert c.unlock('already-unlocked-wrong-input',role,wrong=True)['stage']=='already-unlocked'
  c.retire('client-retire',role);c.retire('client-absent',role)
  c.e['cells'].append({'mode':'smoke','finiteInitializerJoined':True,'lockedRefusal':True,'wrongSecretStayedLocked':True,'freshUnlock':True,'alreadyUnlockedIsAvailabilityOnly':True,'freshRetireAndRepeatedAbsence':True})
 else:
  h,cl=roles['host'],roles['client']
  assert h['greeting']['epoch']!=cl['greeting']['epoch'] and h['greeting']['origin']!=cl['greeting']['origin']
  assert all(x.joined for x in c.children)
  probes=[]
  for own,peer in [(h,cl),(cl,h)]:
   script="from pathlib import Path;import sys;r,control,ownsecret,peer,peercontrol,peersecret=map(Path,sys.argv[1:]);assert (r/'agreement.json').read_bytes();assert (control/'owner.json').read_bytes();assert list(ownsecret.iterdir());n=0\nfor p in [peer,peercontrol,peersecret]:\n for action in [lambda p=p:list(p.iterdir()),lambda p=p:(p/'denied-write').write_bytes(b'x')]:\n  try:action()\n  except PermissionError:n+=1\nassert n==6;print('own root/control accessible; peer root/control/secret read/write denied')"
   child=c.command(own['role']+'-confinement',['-c',script,own['root'],own['control'],own['secret'].parent,peer['root'],peer['control'],peer['secret'].parent],program='/usr/bin/python3',denied=own['denied'],network=False)
   probes.append({'pid':child.p.pid,'joined':child.joined,'peerRootControlAndSecretDenied':True})
  c.e['filesystemDenial']=probes
  hostreport=c.run/'reports/original-host.json';clientreport=c.run/'reports/original-client.json'
  host=c.child('original-host',['durable-independent','host','--root',h['root'],'--report',hostreport,'--progress'],denied=h['denied'])
  assert host.until(lambda v:v.get('stage')=='listening',30)
  c.unlock('active-host-unlock-refused',h,expected=1)
  assert 'BootstrapError' in (c.run/'logs/active-host-unlock-refused.stderr').read_text()
  assert h['root'].exists() and json.loads(Path(str(h['receipt'])+'.state.json').read_text())['phase']=='ready'
  client=c.child('original-client',['durable-independent','begin','--root',cl['root'],'--request',args.requests/'ordinary.json','--report',clientreport,'--progress'],denied=cl['denied'])
  cut=None
  if args.mode=='recovery':
   cut=client.until(lambda v:v.get('stage')=='batch-persisted' and v.get('high',0)>=4,60);assert cut
   client.pause();host.pause()
   assert client.stop()==0;assert host.stop()==0
   original=json.loads(clientreport.read_text());originalHost=json.loads(hostreport.read_text())
   assert original['registered'] and original['inbox'] and original['retention'] and original['accepted']['context']
   assert originalHost['nativeCalls']>0 and not original['terminal']
   assert all(x.joined for x in c.children)
   for role in roles.values():
    c.lock(role['role']+'-lock',role);c.worker_refusal(role['role']+'-locked-worker',role)
   c.unlock('client-wrong-unlock',cl,wrong=True,expected=1);assert c.status('client-still-locked',cl) is False
   for role in roles.values():assert c.unlock(role['role']+'-fresh-unlock',role)['stage']=='unlocked'
   c.e['unlockRecovery']={'bothContainersConfirmedLocked':True,'freshWorkersRefusedWhileLocked':True,'wrongSecretStayedLocked':True,'bothFreshUnlocks':True}
   hostreport=c.run/'reports/recovered-host.json';clientreport=c.run/'reports/recovered-client.json'
   host=c.child('recovered-host',['durable-independent','host','--root',h['root'],'--report',hostreport,'--progress'],denied=h['denied'])
   assert host.until(lambda v:v.get('stage')=='listening',30)
   client=c.child('recovered-client',['durable-independent','recover','--root',cl['root'],'--report',clientreport,'--progress'],denied=cl['denied'])
  assert client.join(240)==0;assert host.stop()==0
  result=json.loads(clientreport.read_text());observed=json.loads(hostreport.read_text())
  assert result['registered'] and result['terminal'] and result['acquisition']['modelLoads']==0 and result['nativeCalls']==0
  assert result['acquisition']['storageLoads']==['client-metadata']
  for role in roles.values():assert json.loads((role['root']/'bootstrap/ready.json').read_text())==role['ready']
  if args.mode=='recovery':
   reference=json.loads((args.reference/'reports/original-client.json').read_text())
   referenceHost=json.loads((args.reference/'reports/original-host.json').read_text())
   assert result['inbox']==reference['inbox'] and observed['binding']==referenceHost['binding']
   assert result['retention']==original['retention'] and result['beforeRecovery'] and result['beforeRecovery'][0]
   for key in ['context','contextDigest','reference']:assert result['accepted'][key]==original['accepted'][key]
   assert all(observed[k]==0 for k in ['requestPreparations','templateCalls','requestTokenizations','issues','begins'])
   assert observed['nativeCalls']>0 and observed['traces'][0]['prepares']==0 and observed['traces'][0]['offsets'][0]>0
  else:assert observed['requestPreparations']==observed['issues']==observed['begins']==1
  terminalHostReport=c.run/'reports/terminal-host.json';terminalClientReport=c.run/'reports/terminal-client.json'
  host=c.child('terminal-host',['durable-independent','host','--root',h['root'],'--report',terminalHostReport,'--progress'],denied=h['denied'])
  assert host.until(lambda v:v.get('stage')=='listening',30)
  c.command('terminal-client',['durable-independent','recover','--root',cl['root'],'--report',terminalClientReport],denied=cl['denied'])
  assert host.stop()==0
  terminal=json.loads(terminalClientReport.read_text());th=json.loads(terminalHostReport.read_text())
  assert terminal['inbox']==result['inbox'] and terminal['retention']==result['retention'] and th['nativeCalls']==0
  assert all(x.joined for x in c.children)
  if args.mode=='recovery':
   c.lock('expired-client-lock',cl)
   time.sleep(31) # The observed native work fits the original 30-second cap; no lease is renewed.
   (cl['root']/'bootstrap/client/current').write_bytes(b'expired content must not be decrypted for unlock or retirement')
   assert c.unlock('expired-client-unlock',cl)['stage']=='unlocked'
   c.e['expiredUnlockRetirement']={'capSeconds':30,'waitAfterTerminalSeconds':31,'confirmedLockedBeforeExpiry':True,'expiredClientManifestMadeUndecodable':True,'freshUnlock':True}
  c.retire('client-retire',cl);c.retire('host-retire',h)
  c.e['cells'].append({'mode':args.mode,'route':'ordinary','cut':cut,'high':result['high'],'nativeCalls':observed['nativeCalls'],'initializersJoinedBeforeWorkers':True,'bothWorkersJoinedBeforeRecovery':args.mode=='recovery','originalAuthorityAndDeadlinePreserved':True,'terminalGenerationCalls':th['nativeCalls'],'freshRetireBothRoles':True})
 c.sample()
except BaseException as error:
 problem=error;raise
finally:c.finish(problem)
