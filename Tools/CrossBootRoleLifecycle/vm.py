from pathlib import Path
import datetime,hashlib,json,os,re,shutil,subprocess,time

INFRA=Path('/Users/nellymoon/.codex/visualizations/2026/09/02/01a0608f-a379-7f80-b83c-e04f351475b4/threshold-vm-infra')
TART=INFRA/'tooling/tart-2.36.0-local.app/Contents/MacOS/tart'
STORE=INFRA/'tart-home';GOLD='threshold-macos27-b6-gold-uiauto-rpcfix-0907'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

class VM:
 def __init__(self,root,name):
  self.root=root;self.e=root/'evidence';self.e.mkdir(mode=0o700);self.name=name;self.target=STORE/'vms'/name
  self.guest='/Users/threshold-auto/'+name;self.shares=root/'shares'
  self.env=dict(os.environ,TART_HOME=str(STORE),TART_NO_AUTO_PRUNE='1',DO_NOT_TRACK='1')
  for key in ['TRACEPARENT','OTEL_EXPORTER_OTLP_TRACES_ENDPOINT','OTEL_EXPORTER_OTLP_HEADERS','OTEL_RESOURCE_ATTRIBUTES']:self.env.pop(key,None)
  self.children=[];self.commands=[];self.samples=[];self.counter=0;self.boot=None;self.bootLog=None;self.bootLabel=None
  self.baseFree=shutil.disk_usage(root).free;self.sample()
 def save(self):
  write(self.e/'children.json',self.children);write(self.e/'commands.json',self.commands);write(self.e/'resources.json',self.samples)
 def sample(self):
  free=shutil.disk_usage(self.root).free;largest=max([p.stat().st_size for p in self.e.glob('*.log')] or [0])
  sample={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'freeBytes':free,'volumeFreeDropBytes':max(0,self.baseFree-free),'largestLogBytes':largest}
  self.samples.append(sample)
  assert free>=30<<30 and sample['volumeFreeDropBytes']<=20<<30 and largest<=192<<20,'sampled resource ceiling'
 def run(self,label,args,body=None,timeout=60,allowFailure=False,vmProcessesOnly=False):
  self.sample();self.counter+=1;key=f'{self.counter:03d}-{label}'
  command=list(map(str,args));entry={'label':label,'command':command,'stdinSHA256':hashlib.sha256(body).hexdigest() if body is not None else None}
  self.commands.append(entry);start=time.monotonic()
  p=subprocess.Popen(command,stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env)
  timedOut=False
  try:out,err=p.communicate(body,timeout=timeout)
  except subprocess.TimeoutExpired:
   timedOut=True;p.terminate()
   try:out,err=p.communicate(timeout=10)
   except subprocess.TimeoutExpired:p.kill();out,err=p.communicate(timeout=10)
  if vmProcessesOnly:
   found=[]
   for line in out.decode().splitlines():
    fields=line.strip().split(None,2)
    if len(fields)==3 and (Path(fields[2]).name.lower() in ['tart','lume','prl_vm_app','qemu-system-aarch64','qemu-system-x86_64'] or 'virtualization' in Path(fields[2]).name.lower()):found.append({'pid':int(fields[0]),'ppid':int(fields[1]),'executable':fields[2]})
   out=(json.dumps(found,sort_keys=True)+'\n').encode()
  (self.e/(key+'.stdout.log')).write_bytes(out);(self.e/(key+'.stderr.log')).write_bytes(err)
  receipt={'label':label,'pid':p.pid,'command':command,'exitCode':p.returncode,'joined':True,'timedOut':timedOut,'seconds':time.monotonic()-start,'stdoutSHA256':hashlib.sha256(out).hexdigest(),'stderrSHA256':hashlib.sha256(err).hexdigest(),'onlyVMProcessNamesRetained':vmProcessesOnly}
  self.children.append(receipt);write(self.e/(key+'.json'),receipt);self.sample();self.save()
  if (p.returncode!=0 or timedOut) and not allowFailure:raise RuntimeError(label+' failed: '+str(p.returncode)+' '+err.decode(errors='replace')[-1500:])
  return p.returncode,out,err
 def tart(self,label,*args,**kwargs):return self.run(label,[TART,*args],**kwargs)
 def rpc(self,label,script,user=False,**kwargs):
  self.commands.append({'label':label,'guestScript':script if len(script)<8192 else None,'guestScriptSHA256':hashlib.sha256(script.encode()).hexdigest(),'automationUser':user})
  prefix=['/bin/launchctl','asuser','503','/usr/bin/sudo','-H','-u','threshold-auto'] if user else []
  return self.run(label,[TART,'exec','-i',self.name,*prefix,'/bin/zsh','-s'],body=script.encode(),**kwargs)
 def user_exec(self,label,args,body=None,**kwargs):
  return self.run(label,[TART,'exec','-i',self.name,'/bin/launchctl','asuser','503','/usr/bin/sudo','-H','-u','threshold-auto',*args],body=body,**kwargs)
 def baseline(self,label):
  expected={'config.json':'94bdd7d4a62fa252cb8ddd37a1663df10502af8347e1c25cbf9f8112dfb577a6','nvram.bin':'cbba3e5e1e513f4e76ef42882d2a68f0c99126de34f4f61ca443d8cf99cadc91'}
  gold=STORE/'vms'/GOLD;actual={name:sha(gold/name) for name in expected};assert actual==expected
  assert sha(TART)=='7c6100b255e5b017501787851e40b0f876d00254dcb6431b7cc51ba410f10738'
  assert not (gold/'state.vzvmsave').exists() and not (gold/'control.sock').exists() and (gold/'disk.img').stat().st_size==150000000000
  write(self.e/('baseline-'+label+'.json'),{'gold':str(gold),'bindings':actual,'tart':str(TART),'tartSHA256':sha(TART),'diskLogicalBytes':150000000000,'savedStateAbsent':True,'controlSocketAbsent':True})
 def idle(self,label):
  _,out,_=self.tart('inventory-'+label,'list','--format','json');assert not [v['Name'] for v in json.loads(out) if v['Running']],'competing VM ownership'
  _,out,_=self.run('process-inventory-'+label,['/bin/ps','-axo','pid=,ppid=,comm='],vmProcessesOnly=True);assert not json.loads(out),'competing VM process'
 def clone(self):
  self.baseline('before');self.idle('pre-clone');assert not self.target.exists() and not self.target.is_symlink()
  for name in ['RunnerSeed','ProvisioningExchange']:(self.shares/name).mkdir(parents=True,mode=0o700)
  self.tart('clone','clone',GOLD,self.name);self.tart('configure-owned-clone','set',self.name,'--cpu','4','--memory','8192')
  actual=json.loads((self.target/'config.json').read_text());original=json.loads((STORE/'vms'/GOLD/'config.json').read_text())
  assert actual['cpuCount']==4 and actual['memorySize']==8<<30
  differences=sorted(k for k in actual.keys()|original.keys() if actual.get(k)!=original.get(k));assert differences==['cpuCount','displayRefit','macAddress','memorySize']
  write(self.e/'clone.json',{'name':self.name,'configSHA256':sha(self.target/'config.json'),'nvramSHA256':sha(self.target/'nvram.bin'),'changedFields':differences,'diskLogicalBytes':(self.target/'disk.img').stat().st_size})
 def start(self,label):
  self.idle('pre-'+label);self.baseline('pre-'+label);self.sample();assert self.boot is None
  args=[str(TART),'run','--no-graphics','--no-audio','--no-clipboard','--suspendable',*['--dir='+n+':'+str(self.shares/n)+':ro' for n in ['RunnerSeed','ProvisioningExchange']],self.name]
  self.bootLabel=label;self.bootLog=(self.e/(label+'.log')).open('xb');self.bootStart=time.monotonic();self.boot=subprocess.Popen(args,env=self.env,stdout=self.bootLog,stderr=subprocess.STDOUT)
  self.commands.append({'label':label,'command':args});write(self.e/(label+'-owned.json'),{'vm':self.name,'pid':self.boot.pid,'command':args})
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   if self.boot.poll() is not None:
    self.join_boot(startupFailure=True);raise RuntimeError('owned boot exited during startup')
   code,out,_=self.rpc(label+'-readiness','set -eu\n[[ $EUID == 0 ]]\n[[ $(/usr/bin/stat -f %u /dev/console) == 503 ]]\n/usr/local/libexec/threshold-automation-preflight enforce\n/usr/bin/shasum -a 256 /usr/local/libexec/threshold-tart-guest-agent\n/usr/sbin/sysctl -n kern.bootsessionuuid\n/usr/bin/sw_vers\n',timeout=8,allowFailure=True)
   if code==0 and b'e520451185ec1ec64727d317ac6733ab33b80acec8b361f49250269f8ac4f7ab' in out:
    write(self.e/(label+'-ready.json'),{'vm':self.name,'rootVSOCK':True,'uid':503,'headless':True,'guestNetworkGateEnforcedBeforeFixtureWork':True,'networkClaim':'Verified baseline attachment and persisted gate; no exhaustive boot packet history.'});print(label+' READY',flush=True);return
   time.sleep(1)
  raise RuntimeError('owned boot readiness timeout')
 def join_boot(self,startupFailure=False):
  code=self.boot.wait(timeout=30);self.bootLog.close()
  receipt={'label':self.bootLabel,'pid':self.boot.pid,'exitCode':code,'joined':True,'vm':self.name,'startupFailure':startupFailure,'seconds':time.monotonic()-self.bootStart}
  self.children.append(receipt);write(self.e/(self.bootLabel+'-joined.json'),receipt);self.boot=None;self.bootLog=None;self.save()
  return code
 def stop(self,label):
  if self.boot is None:return
  if self.boot.poll() is None:
   self.rpc(label+'-flush','set -eu\n[[ $EUID == 0 ]]\n/usr/local/libexec/threshold-automation-preflight enforce\n/bin/sync\n',timeout=20)
   self.tart(label+'-stop','stop',self.name,timeout=30)
  code=self.join_boot();assert code==0
  _,out,_=self.tart(label+'-state','get',self.name,'--format','json');state=json.loads(out)
  assert not state['Running'] and state['State']=='stopped' and not (self.target/'state.vzvmsave').exists()
  write(self.e/(label+'-poweroff.json'),{'state':state,'savedStateAbsent':True});print(label+' STOPPED AND JOINED',flush=True)
 def dispose(self):
  assert self.boot is None;self.baseline('before-disposal');self.tart('dispose-owned-clone','delete',self.name);assert not self.target.exists()
  shutil.rmtree(self.shares);self.baseline('after-disposal');self.save()
