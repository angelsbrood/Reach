#!/usr/bin/env python3
"""S100 ordinary native feasibility: same normal daemon and existing native cells."""
import argparse,hashlib,json,os,selectors,shutil,stat,subprocess,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(sys.argv[1]).resolve(strict=True)
assert str(BASE).startswith('/private/tmp/reach-s100.') and os.getuid()==503
assert BASE.stat().st_uid==503 and stat.S_IMODE(BASE.stat().st_mode)==0o700
sys.path.insert(0,str(BASE/'existing-local-runner'))
import run as ordinary
import native

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
# The cached guest's standard Python may predate hashlib.file_digest.
ordinary.digest=sha

class Child(ordinary.Child):
    def __init__(self,campaign,label,args,*,external=False):
        self.campaign=campaign;self.label=label
        self.out=(campaign.path/'logs'/(label+'.stdout')).open('xb')
        self.err=(campaign.path/'logs'/(label+'.stderr')).open('xb')
        command=list(map(str,args if external else [campaign.executable,*args]))
        # The whole guest controller already has this one outer sandbox.
        self.process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True)
        self.buffer=b'';os.set_blocking(self.process.stdout.fileno(),False)
        self.selector=selectors.DefaultSelector();self.selector.register(self.process.stdout,selectors.EVENT_READ)
        self.record=dict(label=label,pid=self.process.pid,command=command,joined=False,
                         inheritedSandbox='(version 1)(allow default)(deny network*)')
        campaign.evidence['processes'].append(self.record);campaign.save()
    def until(self,predicate,timeout=180):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            self.campaign.sample()
            for _key,_event in self.selector.select(0.01):
                data=os.read(self.process.stdout.fileno(),65536)
                self.out.write(data);self.out.flush();self.buffer+=data
                assert len(self.buffer.split(b'\n',1)[0])<=65536,'bounded control frame'
                while b'\n' in self.buffer:
                    line,self.buffer=self.buffer.split(b'\n',1)
                    assert len(line)<=65536
                    try:value=json.loads(line)
                    except (ValueError,UnicodeDecodeError):continue
                    if predicate(value):return value
            if self.process.poll() is not None:return None
        raise TimeoutError(self.label)
ordinary.Child=Child

class Campaign(ordinary.Campaign):
    def __init__(self,mode,reference=None):
        self.args=argparse.Namespace(mode=mode,routes=['ordinary'],reference_dir=reference)
        self.scratch=ordinary.directory(BASE)
        self.model=ordinary.directory(BASE/'fixtures/model')
        self.requests=ordinary.directory(BASE/'fixtures/requests')
        self.path=BASE/mode;self.path.mkdir(mode=0o700)
        for name in ['bin','reports','logs','roots']:(self.path/name).mkdir(mode=0o700)
        self.executable=self.path/'bin/reachd';shutil.copyfile(BASE/'bin/reachd',self.executable);self.executable.chmod(0o700)
        shutil.copyfile(BASE/'bin/mlx.metallib',self.path/'bin/mlx.metallib')
        self.evidence=dict(executable=str(self.executable),sha256=sha(self.executable),bytes=self.executable.stat().st_size,
            metallibSHA256=sha(self.path/'bin/mlx.metallib'),profileSHA256=sha(self.model/'profile.json'),
            supervisorSHA256=sha(__file__),existingSupervisorSHA256=sha(BASE/'existing-local-runner/run.py'),
            existingNativeCellsSHA256=sha(BASE/'existing-local-runner/native.py'),processes=[],cells=[],resources=[])
        self.last_sample=0;self.sample(force=True);self.save()
    def sample(self,force=False):
        super().sample(force)
        assert shutil.disk_usage(BASE).free>=30<<30

record={'result':'RUNNING','scope':'ordinary same-boot native guest feasibility only','processes':[],'campaigns':[]}
current=None
try:
    # Same authored fixture boundary used by the accepted original-role runner.
    # This happens before either ordinary root is created.
    command=['/usr/bin/osascript','-l','JavaScript','-e','ObjC.import("Foundation"); $.NSProcessInfo.processInfo.operatingSystemVersionString.js']
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out,err=p.communicate(timeout=20)
    record['processes'].append({'label':'guest-backend','pid':p.pid,'exitCode':p.returncode,'joined':True,'command':command})
    assert p.returncode==0
    observed=out.decode().strip();assert observed.startswith('Version ') and '(Build ' in observed
    modelPath=BASE/'fixtures/public-model.json';old=json.loads(modelPath.read_text());value=json.loads(json.dumps(old))
    before=sha(modelPath);value['descriptor']['backend']='arm64-little-endian;cpu;'+observed
    modelPath.write_text(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False));modelPath.chmod(0o600)
    originalBackend=old['descriptor']['backend'];old['descriptor']['backend']=value['descriptor']['backend'];assert old==value
    record['fixtureAuthoring']={'originalHostBackend':originalBackend,'actualGuestBackend':value['descriptor']['backend'],
        'hostPublicModelSHA256':before,'guestPublicModelSHA256':sha(modelPath),'onlyBackendFieldSelected':True,'beforeOriginalRoles':True}
    # Use the installed CLT compiler directly: the /usr/bin driver shim on this
    # cached guest reported an empty InstalledDir and attempted to execute "".
    command=['/usr/bin/xcrun','--find','clang++']
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out,err=p.communicate(timeout=20)
    record['processes'].append({'label':'selected-guest-compiler','pid':p.pid,'exitCode':p.returncode,'joined':True,'command':command,
                               'stdout':out.decode(errors='replace'),'stderr':err.decode(errors='replace')})
    assert p.returncode==0
    compiler=Path(out.decode().strip());assert compiler.is_file() and str(compiler).startswith('/Library/Developer/CommandLineTools/')
    os.environ['PATH']=str(compiler.parent)+':'+os.environ.get('PATH','/usr/bin:/bin:/usr/sbin:/sbin')
    temporary=BASE/'tmp';temporary.mkdir(mode=0o700);os.environ['TMPDIR']=str(temporary)
    probe=temporary/'compiler-probe.cpp';probe.write_text('#include <cmath>\nextern "C" double s100_probe(double x) { return std::exp(x); }\n')
    record['compilerSelection']={'compiler':str(compiler),'compilerSHA256':sha(compiler),'selectedGPlusPlus':shutil.which('g++'),
        'path':os.environ['PATH'],'temporaryDirectory':str(temporary),'sdk':os.environ.get('SDKROOT'),'changesBeforeOriginalRoles':True}
    command=['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path']
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE);out,err=p.communicate(timeout=20)
    record['processes'].append({'label':'selected-guest-sdk','pid':p.pid,'exitCode':p.returncode,'joined':True,'command':command,
                               'stdout':out.decode(errors='replace'),'stderr':err.decode(errors='replace')})
    assert p.returncode==0
    sdk=Path(out.decode().strip());assert sdk.is_dir() and str(sdk).startswith('/Library/Developer/CommandLineTools/')
    record['compilerSelection']['sdk']=str(sdk)
    headers=sdk/'usr/include/c++/v1';assert (headers/'cmath').is_file()
    record['compilerSelection']['cxxHeaders']=str(headers)
    record['compilerSelection']['cmathSHA256']=sha(headers/'cmath')
    selected=None
    record['compilerSelection']['driverAttempts']=[]
    for label,flags in [('absolute-cached-sdk-headers',['-no-canonical-prefixes','-isysroot',str(sdk),'-isystem',str(headers)])]:
        library=temporary/('compiler-probe-'+label+'.so')
        command=[str(compiler),*flags,'-std=c++17','-O3','-Wall','-fPIC','-shared',str(probe),'-o',str(library)]
        p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE);out,err=p.communicate(timeout=30)
        receipt={'label':'guest-compiler-'+label,'pid':p.pid,'exitCode':p.returncode,'joined':True,'command':command,
                 'stdout':out.decode(errors='replace'),'stderr':err.decode(errors='replace')}
        record['processes'].append(receipt);record['compilerSelection']['driverAttempts'].append(receipt)
        if p.returncode==0:
            import ctypes
            probeLibrary=ctypes.CDLL(str(library));probeLibrary.s100_probe.argtypes=[ctypes.c_double];probeLibrary.s100_probe.restype=ctypes.c_double
            assert probeLibrary.s100_probe(0)==1.0
            selected=(label,flags);break
    assert selected is not None,'cached guest compiler cannot compile/load under tested explicit path selections'
    # MLX calls g++ by name. This owned shim forwards unchanged compile arguments
    # to that same installed compiler with only the proven path-selection flags.
    launcher=BASE/'compiler-launcher';launcher.mkdir(mode=0o700)
    shim=launcher/'g++'
    shim.write_text('#!/usr/bin/python3\nimport os,sys\nos.execv('+repr(str(compiler))+', ['+repr(str(compiler))+']+'+repr(selected[1])+'+sys.argv[1:])\n')
    shim.chmod(0o700);os.environ['PATH']=str(launcher)+':'+os.environ['PATH']
    assert 'MLX_DISABLE_COMPILE' not in os.environ
    record['compilerSelection'].update(selectedVariant=selected[0],driverFlags=selected[1],launcherSHA256=sha(shim),
                                      launcherPath=str(shim),nativeCompileDisabled=False)
    record['compilerSelection']['preflightCompiledAndLoaded']=True
    write(BASE/'native-result.json',record)
    for mode in ['crash','reference']:
        current=Campaign(mode,str(BASE/'crash/reports') if mode=='reference' else None)
        native.run(current)
        current.sample(force=True)
        assert all(x['joined'] for x in current.evidence['processes'])
        assert not list((current.path/'roots').iterdir())
        reports={q.name:json.loads(q.read_text()) for q in (current.path/'reports').glob('*.json')}
        assert all(q.get('nativePeak',0)<=128<<20 for q in reports.values())
        current.evidence['result']='PASS';current.save()
        record['campaigns'].append({'mode':mode,'result':'PASS','evidenceSHA256':sha(current.path/'evidence.json'),
            'nativePeaks':{n:q.get('nativePeak') for n,q in reports.items()}})
        print('EARNED ordinary '+mode,flush=True)
    record.update(result='PASS',sameBootOnly=True,positiveCheckpointThenFreshProcessResume=True,
                  zeroNativeTerminalReplay=True,uninterruptedReferenceMatched=True,originalCreatorsRetired=True)
except BaseException as error:
    record.update(result='FAIL',failure=str(error),traceback=traceback.format_exc())
    if current:
        current.evidence.update(result='FAIL',failure=repr(error));current.save()
        if 'cleanupGuardianPID' in current.evidence:record['cleanupGuardianPID']=current.evidence['cleanupGuardianPID']
finally:
    record['rootObservations']={str(q.relative_to(BASE)):q.exists() for mode in ['crash','reference'] for q in (BASE/mode/'roots').glob('*')}
    record['keychainPaths']=[str(q.relative_to(BASE)) for q in BASE.rglob('*.keychain-db')]
    record['controllerPID']=os.getpid()
    write(BASE/'native-result.json',record)
    print(json.dumps(record,sort_keys=True),flush=True)
sys.exit(0 if record['result']=='PASS' else 1)
