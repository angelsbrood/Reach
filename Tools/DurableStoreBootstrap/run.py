#!/usr/bin/env python3
"""S85 offline bootstrap/key candidate. No root keys cross the surviving supervisor."""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).resolve().parent
INPUTS_SHA = "4a49528cc05b6a8cf5080ba1efd59cb0411c9580a378f22a98160dbc50135169"
S82_RUN_SHA = "29ebccbd15efecb9940b376e12e4270fa68a29cf50caee0e7c4a9f7e77c6e6da"
GIB = 1 << 30

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def save(path,value): path.write_text(json.dumps(value,indent=2)+"\n")

class Worker:
    def __init__(self,campaign,binary,config,label):
        self.c=campaign; self.label=label; self.log_path=campaign.logs/(label+".log"); self.log=self.log_path.open("wb")
        assert sha(binary)==campaign.binaries[binary.name], "frozen worker bytes"
        self.p=subprocess.Popen([str(binary)],cwd=campaign.package,env=campaign.env,stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=self.log,start_new_session=True,bufsize=0)
        campaign.children.append(self.p); campaign.worker_objects.append(self)
        self.send(config); self.ready=self.read()
    def send(self,message):
        assert not {"key","ticketKey","catalogKey","metadataKey","rootKeys"}.intersection(message), "no root-key message fields"
        body=encoded(message); replay="frame" in message
        assert 0<len(body)<=((12 if replay else 2)<<20)
        for part in (bytes([int(replay)])+struct.pack(">I",len(body)),body):
            rest=memoryview(part)
            while rest:
                n=os.write(self.p.stdin.fileno(),rest[:65536]); assert n>0; rest=rest[n:]
    def exact(self,count):
        result=bytearray(); deadline=time.monotonic()+60
        with selectors.DefaultSelector() as selector:
            selector.register(self.p.stdout,selectors.EVENT_READ)
            while len(result)<count:
                assert selector.select(max(0,deadline-time.monotonic())), "bounded IPC deadline"
                chunk=os.read(self.p.stdout.fileno(),min(65536,count-len(result))); assert chunk,"worker ended before reply"
                result.extend(chunk)
        return bytes(result)
    def read(self):
        header=self.exact(5); assert header[0] in (0,1)
        count=struct.unpack(">I",header[1:])[0]; assert 0<count<=((12 if header[0] else 2)<<20)
        body=self.exact(count); value=json.loads(body)
        assert encoded(value)==body and ("frame" in value)==bool(header[0])
        if "peak" in value:
            assert value["peak"]<=128<<20; self.c.mlx_peak=max(self.c.mlx_peak,value["peak"])
        return value
    def request(self,action,**fields): self.send(dict(action=action,**fields)); return self.read()
    def join(self,killed=False,expected=0):
        if killed: self.p.kill(); expected=-signal.SIGKILL
        self.p.wait(timeout=30); assert self.p.returncode==expected,"worker exit"
        assert not self.p.stdout.read(4097),"unconsumed protocol output"
        self.p.stdin.close(); self.p.stdout.close(); self.log.close()
        self.c.commands.append(dict(label=self.label,pid=self.p.pid,exit_code=self.p.returncode,log_sha256=sha(self.log_path)))
        self.c.sample()
    def close(self):
        assert self.request("close")["action"]=="closed"; self.join()

class Scenario:
    def __init__(self,campaign,label):
        self.c=campaign; self.label=label; self.root=campaign.fixtures/label; self.generation="g-1"
        self.host_config=dict(action="open",root=str(self.root),optIn=True,fresh=False)
        self.client_config=dict(self.host_config)
        self.host=campaign.worker("HostBootstrapWorker",dict(self.host_config,fresh=True,
            container=str(campaign.fixtures/"containers/primary.keychain-db"),workers=campaign.worker_bindings),label+"-create")
        assert self.host.ready["action"]=="ready" and self.host.ready["keyCreates"]==3 and self.host.ready["keyLoads"]==2
        self.identity={k:self.host.ready[k] for k in ("bootstrapID","hostID","clientID","boot")}
        issued=self.host.request("issue"); assert issued["action"]=="ok" and issued.get("ticket")
        self.host_config["ticket"]=issued["ticket"]
        result=self.host.request("begin",generation=self.generation,route="ordinary")
        assert result["action"]=="ok" and result.get("context")
        self.authority=result["context"]; self.client_config["context"]=self.authority
        self.client=self.reopen_client(); self.witness=self.client.ready["witness"]
        self.frames=[]; self.native_calls=0
    def check_identity(self,worker,role):
        assert worker.ready["action"]=="ready"
        assert all(worker.ready[k]==v for k,v in self.identity.items()),"original descriptor IDs"
        assert worker.ready["keyCreates"]==0 and worker.ready["keyLoads"]==(2 if role=="host" else 1),"independent role-only acquisition"
    def reopen_client(self):
        worker=self.c.worker("ClientBootstrapWorker",self.client_config,self.label+"-client")
        self.check_identity(worker,"client"); return worker
    def reopen_host(self):
        worker=self.c.worker("HostBootstrapWorker",self.host_config,self.label+"-host-reopen")
        self.check_identity(worker,"host"); return worker
    def attach(self):
        result=self.host.request("attach",generation=self.generation,route="ordinary",witness=self.witness)
        assert result["action"]=="ok" and result["context"]==self.authority
    def receipt(self): return self.host.request("receipt",generation=self.generation,witness=self.witness)
    def drain(self):
        cursor=self.witness["high"]; self.host.send(dict(action="replay",cursor=cursor))
        while True:
            response=self.host.read()
            if response["action"]=="replay-end": return
            assert response["action"]=="batch"
            frame=response["frame"]; self.frames.append(frame)
            result=self.client.request("accept",frame=frame,cursor=cursor); assert result["action"]=="ok"
            self.witness=result["witness"]; self.host.send(dict(action="next"))
    def step(self):
        assert self.receipt()["action"]=="ok"
        result=self.host.request("step"); assert result["action"]=="ok"
        self.native_calls=max(self.native_calls,result["calls"]); self.drain()
    def drive(self):
        for _ in range(600):
            if self.witness["terminal"]: return
            self.step()
        raise AssertionError("bounded ordinary native continuation")
    def events(self):
        high=0; events=[]
        for frame in self.frames:
            assert frame["first"]==high+1 and frame["skip"]==0
            batch=json.loads(base64.b64decode(frame["bytes"],validate=True)); assert len(batch)==frame["count"]
            events.extend(batch); high+=len(batch)
        assert high==self.witness["high"]; return events
    def retire(self):
        assert self.host.request("validate")["action"]=="ok" and self.native_calls>0 and self.witness["terminal"]
        result=self.receipt(); assert result["action"]=="ok" and result["phase"]=="tombstone"
        assert result["terminal"] and result["high"]==self.witness["high"] and result["disposition"].startswith("durable-receipt-v1:")
        self.disposition=result["disposition"]
        assert not any((self.root/"host/children").iterdir()) and not any((self.root/"host/requests").iterdir())
        assert self.client.request("witness")["witness"]==self.witness
    def close(self,remove=True):
        for worker in (self.client,self.host):
            if worker.p.poll() is None: worker.close()
        if remove and self.root.exists(): shutil.rmtree(self.root)

class Campaign:
    def __init__(self,repo):
        os.umask(0o077); self.repo=repo
        self.root=Path(tempfile.mkdtemp(prefix="reach-durable-store-bootstrap.",dir="/private/tmp"))
        self.private=self.root/"private"; self.logs=self.root/"logs"; self.evidence=self.root/"evidence"
        for p in (self.private,self.logs,self.evidence): p.mkdir()
        self.package=self.private/"harness"; self.package.mkdir()
        self.fixtures=self.private/"fixtures"; self.fixtures.mkdir(); (self.fixtures/"containers").mkdir()
        self.env=dict(os.environ,S85_FIXTURES=str(self.fixtures),CLANG_MODULE_CACHE_PATH=str(self.private/"clang-cache"),
            SWIFTPM_MODULECACHE_OVERRIDE=str(self.private/"swift-cache"))
        self.commands=[]; self.children=[]; self.worker_objects=[]; self.observations=[]; self.matrix=[]
        self.mlx_peak=0; self.controller=None; self.container_cleanup=None; self.passwords={}; self.sample()
    def sample(self):
        def allocation(root):
            total=0
            for p in [root,*root.rglob("*")]:
                try: total+=p.lstat().st_blocks*512
                except FileNotFoundError: pass
            return total
        allocated=allocation(self.root)
        if PRODUCT.parent.name.startswith("reach-s85."): allocated+=allocation(PRODUCT.parent)
        fixtures=allocation(self.fixtures); containers=allocation(self.fixtures/"containers"); free=shutil.disk_usage(self.root).free
        assert allocated<=16*GIB and fixtures<=3*GIB and containers<=64<<20 and free>=20*GIB,"S85 resource bounds"
        assert all(p.stat().st_size<=192<<20 for p in self.logs.rglob("*") if p.is_file())
        self.observations.append(dict(allocated=allocated,fixtures=fixtures,containers=containers,free=free))
    def command(self,args,label,cwd=None):
        self.sample(); log=self.logs/(label+".log"); start=time.monotonic()
        with log.open("wb") as output:
            p=subprocess.Popen(args,cwd=cwd or self.package,env=self.env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            self.children.append(p)
            while p.poll() is None:
                try: p.wait(timeout=2)
                except subprocess.TimeoutExpired: self.sample()
        self.commands.append(dict(label=label,command=args,pid=p.pid,exit_code=p.returncode,seconds=time.monotonic()-start,log_sha256=sha(log)))
        self.sample(); assert p.returncode==0,label+" failed; see bounded log"; return log.read_text()
    def export(self,source,target,revision,revisions):
        n=str(len(revisions))
        assert self.command(["git","rev-parse","HEAD"],"revision-"+n,source).strip()==revision
        assert not self.command(["git","status","--porcelain","--untracked-files=no"],"clean-"+n,source).strip()
        revisions[str(source)]=revision; target.mkdir(parents=True,exist_ok=True); assert not any(target.iterdir())
        archive=target.parent/(target.name+".tar")
        self.command(["git","archive","--format=tar","--output="+str(archive),revision],"archive-"+n,source)
        with tarfile.open(archive) as data: data.extractall(target,filter="data")
        archive.unlink()
        for line in self.command(["git","ls-tree","-r",revision],"tree-"+n,source).splitlines():
            if line.startswith("160000 "):
                header,relative=line.split("\t",1); self.export(source/relative,target/relative,header.split()[2],revisions)
    def prepare(self):
        old=self.repo/"Tools/DurableSessionLifecycle/run.py"; assert sha(old)==S82_RUN_SHA
        legacy=runpy.run_path(str(old))  # Accepted constants only; no old campaigns.
        folders=[*legacy["PREREQUISITES"],"DurableSessionLifecycle","DurableClientReceipts","DurableHostClientIntegration"]
        inputs={str(p.relative_to(self.repo)):sha(p) for folder in folders for p in (self.repo/"Tools"/folder).rglob("*") if p.is_file()}
        assert len(inputs)==123
        selected=[*legacy["SELECTED_SOURCES"],"ReachKit/Sources/ReachKit/ReachLanguageModel.swift","ReachKit/Sources/ReachWire/Frames.swift"]
        inputs.update({p:sha(self.repo/p) for p in selected})
        assert len(inputs)==137 and hashlib.sha256(encoded(inputs)).hexdigest()==INPUTS_SHA
        products={str(p.relative_to(PRODUCT)):sha(p) for p in PRODUCT.rglob("*") if p.is_file()}
        assert len(products)==17 and not any(p.is_symlink() for p in PRODUCT.rglob("*"))
        assert sha(self.repo/legacy["METALLIB"])==legacy["METALLIB_SHA"]
        save(self.evidence/"inputs.json",dict(products=products,accepted=inputs,metallib_sha256=legacy["METALLIB_SHA"],pins=legacy["PINS"]))
        revisions={}
        for name,revision in legacy["PINS"].items():
            self.export(self.repo/"reachd/.build/checkouts"/name,self.package/name if name=="mlx-swift-lm" else self.private/name,revision,revisions)
        manifest=self.private/"mlx-swift/Package.swift"; text=manifest.read_text()
        for name in ("swift-numerics","swift-argument-parser"):
            old=f'.package(url: "https://github.com/apple/{name}", from: "1.0.0")'; assert text.count(old)==1
            text=text.replace(old,f'.package(path: "../{name}")')
        manifest.write_text(text)  # Exact accepted offline overlay only.
        lm=self.package/"mlx-swift-lm"
        for n,name in enumerate(legacy["PREREQUISITES"]):
            if "mlx-swift-lm.patch" in legacy["PREREQUISITES"][name]:
                patch=self.repo/"Tools"/name/"mlx-swift-lm.patch"
                self.command(["git","apply","--check",str(patch)],f"patch-check-{n}",lm)
                self.command(["git","apply",str(patch)],f"patch-apply-{n}",lm)
        outputs={p:sha(lm/p) for p in legacy["PRIOR_OUTPUTS"]}; assert outputs==legacy["PRIOR_OUTPUTS"] and len(outputs)==35
        save(self.evidence/"composition.json",dict(revisions=revisions,unchanged_native_outputs=outputs,new_native_outputs=0))
        copied={}
        pairs=[("ResumableRequiredToolCoordinator","RequiredToolCoordinator"),("ResumableAllowedToolCoordinator","AllowedToolCoordinator"),
            ("ResumableMLXProvider","ResumableMLXProvider"),("DurableHostStore","DurableHostStore"),
            ("DurableSessionLifecycle","DurableSessionLifecycle"),("DurableSessionLifecycle","LifecycleFixtures"),
            ("DurableClientReceipts","DurableClientReceipts"),
            *[("DurableHostClientIntegration",m) for m in ("DurableClientReceipts","DurableSessionLifecycle","HostClientContract","HostClientFixtures")]]
        for folder,module in pairs:
            for source in (self.repo/"Tools"/folder/"Sources"/module).glob("*.swift"):
                target=self.package/"Sources"/module/source.name; target.parent.mkdir(parents=True,exist_ok=True)
                assert not target.exists(); shutil.copy2(source,target); copied[str(target.relative_to(self.package))]=sha(source)
        wire=self.package/"Sources/ReachWire/WireEvent.swift"; wire.parent.mkdir(); shutil.copy2(self.repo/"ReachKit/Sources/ReachWire/WireEvent.swift",wire)
        copied[str(wire.relative_to(self.package))]=sha(wire)
        tiny=self.package/"TinyLlama"; tiny.mkdir()
        for p in ("LLMModel.swift","Models/Llama.swift"): shutil.copy2(lm/"Libraries/MLXLLM"/p,tiny/Path(p).name)
        for name in products:
            if name.startswith(("Sources/","Tests/")) or name=="Package.swift":
                target=self.package/name; target.parent.mkdir(parents=True,exist_ok=True); assert not target.exists(); shutil.copy2(PRODUCT/name,target)
        save(self.evidence/"copied-libraries.json",copied)
        self.flags=["--package-path",str(self.package),"--scratch-path",str(self.private/"build"),"--cache-path",str(self.private/"spm-cache"),
            "--config-path",str(self.private/"spm-config"),"--security-path",str(self.private/"spm-security"),"--disable-sandbox","--disable-netrc",
            "--disable-keychain","--disable-dependency-cache","--disable-prefetching","--skip-update","--disable-index-store","--build-system","native","--jobs","4"]
        output=self.command(["xcrun","swift","build",*self.flags,"--show-bin-path"],"binary-path")
        paths=[p for p in output.splitlines() if p.startswith(str(self.private/"build")+"/")]; assert len(paths)==1
        self.binary=Path(paths[0]); self.binary.mkdir(parents=True,exist_ok=True)
        shutil.copy2(self.repo/legacy["METALLIB"],self.binary/"mlx.metallib"); shutil.copy2(self.repo/legacy["METALLIB"],self.package/"default.metallib")
        self.command(["xcrun","swift","build",*self.flags,"--build-tests"],"build")
        for bundle in (self.private/"build").rglob("*.xctest"):
            target=bundle/"Contents/MacOS"; target.mkdir(parents=True,exist_ok=True); shutil.copy2(self.repo/legacy["METALLIB"],target/"mlx.metallib")
        names=["HostBootstrapWorker","ClientBootstrapWorker","KeychainWorker"]
        self.binaries={name:sha(self.binary/name) for name in names}
        self.worker_bindings=[dict(path=str(self.binary/name),sha256=self.binaries[name]) for name in names]
        for name in names[1:]:
            symbols=self.command(["nm","-u",str(self.binary/name)],"cpu-symbols-"+name)
            assert not re.search(r"(?i)(mlx_|cmlx|metal)",symbols),"CPU-only symbol boundary"
        self.inputs=inputs; self.copied=copied; self.outputs=outputs; self.revisions=revisions
    def tests(self,pattern=None):
        args=["--filter",pattern] if pattern else []
        log=self.command(["xcrun","swift","test",*self.flags,"--skip-build","--no-parallel",*args],"tests")
        log=re.sub(r"warning: '--build-system native'[^\n]*\n","",log)
        selected=sorted(re.findall(r"func (test\w+)\(","\n".join(p.read_text() for p in (PRODUCT/"Tests").rglob("*.swift"))))
        if pattern: selected=[n for n in selected if re.search(pattern,n)]
        started=sorted(re.findall(r"Test Case '-\[DurableStoreBootstrapTests\.\w+ (test\w+)\]' started",log))
        passed=sorted(re.findall(r"Test Case '-\[DurableStoreBootstrapTests\.\w+ (test\w+)\]' passed",log))
        assert selected==started==passed and passed
        save(self.evidence/"tests.json",dict(result="PASS",selected=selected,started=started,passed=passed,filter=pattern)); return len(passed)
    def record(self,case,**values):
        self.matrix.append(dict(case=case,**values)); save(self.evidence/"matrix.json",self.matrix); self.sample()
    def worker(self,name,config,label):
        return Worker(self,self.binary/name,config,label+"-"+str(len(self.children)))
    def unavailable(self,name,config,label,stage=None):
        worker=self.worker(name,config,label)
        assert worker.ready["action"]=="unavailable",label
        if stage: assert worker.ready.get("stage")==stage,label+" stage"
        code=worker.ready.get("code"); worker.join(expected=1); return code
    def descriptor(self,root):
        path=root/"ready.json"; info=path.lstat()
        assert not path.is_symlink() and info.st_uid==os.getuid() and info.st_mode&0o777==0o600 and info.st_size<=64<<10
        return json.loads(path.read_bytes())  # Nonsecret descriptor; confirmations are never retained in evidence.
    @staticmethod
    def binding(core): return hashlib.sha256(b"S85/bootstrap-core/v1\0"+encoded(core)).hexdigest()
    def acquisitions(self):
        """Focused proof of the fixed-container guard; no native generation or effect."""
        self.controller=self.worker("KeychainWorker",dict(action="control",workers=self.worker_bindings),"keychain-controller")
        assert self.controller.ready["action"]=="ready", {k:v for k,v in self.controller.ready.items() if k in ("action","stage","code")}
        self.passwords["primary"]=uuid.uuid4().hex+uuid.uuid4().hex
        assert self.controller.request("create",slot="primary",password=self.passwords["primary"])["action"]=="ok"
        root=self.fixtures/"container-binding"
        config=dict(action="open",root=str(root),optIn=True,fresh=False)
        host=self.worker("HostBootstrapWorker",dict(config,fresh=True,container=str(self.fixtures/"containers/primary.keychain-db"),
            workers=self.worker_bindings),"container-create")
        assert host.ready["action"]=="ready" and host.ready["keyCreates"]==3 and host.ready["keyLoads"]==2
        identity={k:host.ready[k] for k in ("bootstrapID","hostID","clientID","boot")}; host.close()
        original_intent=(root/"intent.json").read_bytes(); original_ready=(root/"ready.json").read_bytes()
        changed=json.loads(original_ready); changed["core"]["container"]=str(self.fixtures/"containers/decoy.keychain-db")
        (root/"intent.json").write_bytes(encoded(dict(state="creating",core=changed["core"])))
        (root/"ready.json").write_bytes(encoded(changed))
        for name,role in (("HostBootstrapWorker","host"),("ClientBootstrapWorker","client")):
            before=sha(root/role/"current")
            self.unavailable(name,config,"foreign-container-"+role,"validation")
            assert sha(root/role/"current")==before
        assert not (self.fixtures/"containers/decoy.keychain-db").exists()
        (root/"intent.json").write_bytes(original_intent); (root/"ready.json").write_bytes(original_ready)
        for name,loads in (("HostBootstrapWorker",2),("ClientBootstrapWorker",1)):
            worker=self.worker(name,config,"original-container-reopen")
            assert worker.ready["action"]=="ready" and worker.ready["keyCreates"]==0 and worker.ready["keyLoads"]==loads
            assert all(worker.ready[k]==v for k,v in identity.items()) and "ticket" not in worker.ready
            worker.close()
        self.record("fixed-container-acquisition",changed_container_refused_before_lookup=True,both_journals_unchanged_on_refusal=True,
            original_host_loads=2,original_client_loads=1,key_generation_on_reopen=0,native_generations=0,effects=0,created_items=3)
        shutil.rmtree(root)
    def workers(self):
        for name in ("HostBootstrapWorker","ClientBootstrapWorker"):
            root=self.fixtures/("off-"+name.lower())
            worker=self.worker(name,dict(action="open",root=str(root),optIn=False,fresh=False),"default-off")
            assert worker.ready==dict(action="disabled",keyCreates=0,keyLoads=0) and not root.exists()
            worker.join()
        self.record("default-off",provider_accesses=0,journal_mutations=0)
        self.controller=self.worker("KeychainWorker",dict(action="control",workers=self.worker_bindings),"keychain-controller")
        assert self.controller.ready["action"]=="ready", {k:v for k,v in self.controller.ready.items() if k in ("action","stage","code")}
        for slot in ("primary","decoy"):
            self.passwords[slot]=uuid.uuid4().hex+uuid.uuid4().hex
            result=self.controller.request("create",slot=slot,password=self.passwords[slot])
            assert result["action"]=="ok" and result["metadataPreserved"]

        reference=Scenario(self,"ordinary-reference")
        try:
            descriptor=self.descriptor(reference.root); core=descriptor["core"]; binding=self.binding(core)
            key=core["keys"][0]
            assert self.controller.request("load",reference=key,binding=binding,confirmation=descriptor["confirmations"][0])["action"]=="ok"
            assert self.controller.request("add",reference=key,binding=binding)["stage"]=="duplicate"
            decoy=self.controller.request("load",slot="decoy",reference=key,binding=binding)
            assert decoy["action"]=="refused" and decoy["stage"]=="scoped-load-only" and decoy["code"]==-25300
            before=sha(reference.root/"ready.json")
            reference.host.close()
            self.unavailable("HostBootstrapWorker",dict(action="open",root=str(reference.root),optIn=True,fresh=True,
                container=str(self.fixtures/"containers/primary.keychain-db"),workers=self.worker_bindings),"second-create")
            assert sha(reference.root/"ready.json")==before
            assert self.controller.request("lock")["action"]=="ok"
            assert reference.client.request("witness")["witness"]==reference.witness,"cached live keys survive lock"
            reference.client.close()
            locked=self.unavailable("ClientBootstrapWorker",reference.client_config,"locked-client","scoped-load-only")
            assert locked in (-25293,-25308),"actual locked no-UI OS refusal"
            assert self.controller.request("unlock",password=self.passwords["primary"])["action"]=="ok"
            reference.client=reference.reopen_client(); assert reference.client.ready["witness"]==reference.witness
            reference.host=reference.reopen_host(); reference.attach()
            self.record("real-scoped-keychain",duplicate_add_refused=True,decoy_code=decoy["code"],locked_code=locked,
                independent_host_loads=2,independent_client_loads=1,cached_owner_survived_lock=True,explicit_unlock=True,second_create_unchanged=True)
            reference.drive(); expected=reference.events(); reference.retire()
            self.record("ordinary-reference",native_calls=reference.native_calls,receipt_retired=True)
        finally: reference.close(remove=False)

        for point in ("afterFirstKey","afterReady"):
            root=self.fixtures/("creation-"+point.lower())
            worker=self.worker("HostBootstrapWorker",dict(action="open",root=str(root),optIn=True,fresh=True,
                container=str(self.fixtures/"containers/primary.keychain-db"),workers=self.worker_bindings,boundary=point),"creation-"+point)
            assert worker.ready==dict(action="boundary",boundary=point); worker.join(killed=True)
            config=dict(action="open",root=str(root),optIn=True,fresh=False)
            if point=="afterFirstKey":
                self.unavailable("HostBootstrapWorker",config,"incomplete-reopen","incomplete")
                assert not (root/"ready.json").exists() and not (root/"host").exists() and not (root/"client").exists()
                intent=json.loads((root/"intent.json").read_bytes()); core=intent["core"]; binding=self.binding(core)
                assert self.controller.request("load",reference=core["keys"][0],binding=binding)["action"]=="ok"
                assert self.controller.request("load",reference=core["keys"][1],binding=binding)["code"]==-25300
                self.record("creation-"+point,death=point,incomplete_refused=True,one_key_present=True,stores_absent=True)
            else:
                selected=self.descriptor(root)
                for name,loads in (("HostBootstrapWorker",2),("ClientBootstrapWorker",1)):
                    restored=self.worker(name,config,"ready-reopen")
                    assert restored.ready["action"]=="ready" and restored.ready["keyCreates"]==0 and restored.ready["keyLoads"]==loads
                    assert restored.ready["bootstrapID"]==selected["core"]["identifier"]
                    assert restored.ready["hostID"]==selected["core"]["hostID"] and restored.ready["clientID"]==selected["core"]["clientID"]
                    assert "ticket" not in restored.ready
                    if name=="HostBootstrapWorker":
                        assert restored.request("begin",generation="not-authorized-by-missing-ticket",route="ordinary")["action"]=="refused"
                        assert not any((root/"host/requests").iterdir())
                    restored.close()
                self.record("creation-"+point,death=point,original_ready_reopened=True,key_generation_on_reopen=0,no_implicit_ticket=True)
            shutil.rmtree(root)

        active=Scenario(self,"ordinary-active")
        try:
            for _ in range(600):
                active.step()
                if active.witness["high"]>0: break
            frontier=active.witness["high"]; assert frontier>0 and not active.witness["terminal"]
            assert active.receipt()["action"]=="ok"
            assert active.host.request("step",boundary="afterStep")==dict(action="boundary",boundary="afterStep")
            active.host.join(killed=True); active.host=active.reopen_host(); active.native_calls=0
            active.attach(); active.drain(); active.drive(); actual=active.events()
            assert active.native_calls>0 and actual[:frontier]==expected[:frontier] and actual[frontier:]==expected[frontier:]
            active.retire()
            native_witness=active.witness; native_context=active.authority
            active.client.close(); active.client=active.reopen_client(); assert active.client.ready["witness"]==native_witness
            self.record("active-native-restore",death="afterStep",new_native_calls=active.native_calls,exact_suffix=True,
                original_receipt_reopened=True,receipt_retired=True,root_keys_supplied_by_supervisor=False)

            # Separate bounded synthetic S83 knowledge fixture; not a second native route.
            active.client.close(); knowledge=json.loads(base64.b64decode(native_context))
            knowledge.update(generation="s85-knowledge-fixture",request="s85-knowledge-request",operation="s85-knowledge-operation",route="required",
                upstreamDigest=hashlib.sha256(b"S85/knowledge-fixture/v1"+active.identity["bootstrapID"].encode()).hexdigest())
            active.client_config["context"]=base64.b64encode(encoded(knowledge)).decode()
            active.client=active.reopen_client()
            seeded=active.client.request("seed-knowledge"); assert seeded["action"]=="ok"
            knowledge_witness=seeded["witness"]; effect_count=0
            assert active.client.request("effect")["action"]=="fake-effect"; effect_count+=1
            active.client.send(dict(action="effect-recorded")); known=active.client.read()
            assert known["action"]=="ok" and known["state"]=="known" and base64.b64decode(known["result"])==b"s85-known-result"
            active.client.close(); active.client=active.reopen_client()
            assert active.client.ready["witness"]==knowledge_witness
            for action in ("state","begin","effect"):
                reply=active.client.request(action)
                assert reply["action"]=="ok" and reply["state"]=="known" and base64.b64decode(reply["result"])==b"s85-known-result"
            assert effect_count==1
            self.record("client-knowledge-reopen",synthetic_fixture=True,effects=1,known_exact=True,permission_reissued=False)

            descriptor=self.descriptor(active.root); core=descriptor["core"]; binding=self.binding(core)
            active.host.close(); active.client.close()
            original_intent=(active.root/"intent.json").read_bytes(); original_ready=(active.root/"ready.json").read_bytes()
            for field in ("boot","quota","client-root"):
                changed=json.loads(original_ready); changed_core=changed["core"]
                if field=="boot": changed_core["policy"]["boot"]=str(uuid.uuid4())
                elif field=="quota": changed_core["policy"]["clientQuota"]+=1
                else: changed_core["clientID"]=str(uuid.uuid4())
                (active.root/"intent.json").write_bytes(encoded(dict(state="creating",core=changed_core)))
                (active.root/"ready.json").write_bytes(encoded(changed))
                before=sha(active.root/"client/current")
                self.unavailable("ClientBootstrapWorker",active.client_config,"descriptor-"+field)
                assert sha(active.root/"client/current")==before
                (active.root/"intent.json").write_bytes(original_intent); (active.root/"ready.json").write_bytes(original_ready)
            self.record("descriptor-original-identity",boot_quota_client_root_refused=True,client_journal_unchanged=True)

            wrong=dict(core["keys"][1],role="client-metadata")
            assert self.controller.request("load",reference=wrong,binding=binding)["action"]=="refused"
            assert self.controller.request("replace",reference=core["keys"][1],binding=binding)["action"]=="ok"
            before=sha(active.root/"host/current")
            self.unavailable("HostBootstrapWorker",active.host_config,"replaced-ticket-key")
            assert sha(active.root/"host/current")==before
            active.client=active.reopen_client(); assert active.client.request("state")["state"]=="known"; active.client.close()
            self.record("ticket-key-replacement",correct_label_replacement_refused=True,host_journal_unchanged=True,client_available=True,wrong_role_refused=True)

            assert self.controller.request("delete",reference=core["keys"][0],binding=binding)["action"]=="ok"
            self.unavailable("HostBootstrapWorker",active.host_config,"missing-host-key","scoped-load-only")
            active.client=active.reopen_client(); assert active.client.request("state")["state"]=="known"; active.client.close()
            shutil.rmtree(active.root/"host")
            self.unavailable("HostBootstrapWorker",active.host_config,"missing-host-journal","incomplete")
            active.client=active.reopen_client(); assert active.client.request("state")["state"]=="known"; active.client.close()
            shutil.rmtree(active.root/"client")
            self.unavailable("ClientBootstrapWorker",active.client_config,"missing-client-journal","incomplete")
            assert not (active.root/"host").exists() and not (active.root/"client").exists()
            self.record("independent-unavailability",host_key_missing_client_known=True,host_journal_missing_client_known=True,
                missing_journals_recreated=False,key_generation_on_reopen=0)
        finally: active.close()

        cleanup=self.controller.request("cleanup")
        assert cleanup["action"]=="ok" and cleanup["metadataPreserved"] and cleanup["registrationAbsent"]
        assert not any((self.fixtures/"containers").iterdir())
        before=sha(reference.root/"client/current")
        self.unavailable("ClientBootstrapWorker",reference.client_config,"missing-container")
        assert sha(reference.root/"client/current")==before
        reference.close()
        self.record("missing-container",load_only_refused=True,client_journal_unchanged=True,
            container_files_absent=True,registrations_absent=True,unrelated_metadata_preserved=True,created_item_upper_bound=11)
    def verify(self):
        for p,h in self.inputs.items(): assert sha(self.repo/p)==h
        for p,h in self.copied.items(): assert sha(self.package/p)==h
        assert {p:sha(self.package/"mlx-swift-lm"/p) for p in self.outputs}==self.outputs
        for n,(p,revision) in enumerate(self.revisions.items()):
            assert self.command(["git","rev-parse","HEAD"],f"final-revision-{n}",p).strip()==revision
            assert not self.command(["git","status","--porcelain","--untracked-files=no"],f"final-clean-{n}",p).strip()
    def finish(self,result):
        for p in self.children:
            if p.poll() is None and (self.controller is None or p is not self.controller.p):
                os.killpg(p.pid,signal.SIGKILL); p.wait(timeout=30)
        if self.controller is not None and self.controller.ready.get("action")=="unavailable":
            self.controller.join(expected=1)
        elif self.controller is not None and self.controller.p.poll() is None:
            self.container_cleanup=self.controller.request("cleanup")
            assert self.container_cleanup["action"]=="ok" and self.container_cleanup["metadataPreserved"] and self.container_cleanup["registrationAbsent"]
            self.controller.close()
        assert not any((self.fixtures/"containers").iterdir()),"owned Keychain files absent"
        for worker in self.worker_objects:
            for handle in (worker.p.stdin,worker.p.stdout,worker.log):
                if not handle.closed: handle.close()
        assert all(p.poll() is not None for p in self.children)
        self.sample(); shutil.rmtree(self.private); self.passwords.clear()
        save(self.evidence/"commands.json",self.commands); save(self.evidence/"matrix.json",self.matrix)
        save(self.evidence/"resources.json",dict(maximum_allocated_bytes=max(x["allocated"] for x in self.observations),
            maximum_fixture_boundary_bytes=max(x["fixtures"] for x in self.observations),maximum_container_boundary_bytes=max(x["containers"] for x in self.observations),
            minimum_free_bytes=min(x["free"] for x in self.observations),mlx_worker_peak_bytes=self.mlx_peak,
            observation="Explicit owned children and sampled allocation boundaries; no continuous RSS or exhaustive descendants"))
        result.update(private_removed=True,owned_child_pids_joined=[p.pid for p in self.children],container_cleanup=self.container_cleanup,
            evidence_sha256={p.name:sha(p) for p in self.evidence.iterdir() if p.is_file()})
        save(self.evidence/"results.json",result)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",type=Path,default=PRODUCT.parents[1]); parser.add_argument("--tests-only",action="store_true")
    parser.add_argument("--workers-only",action="store_true"); parser.add_argument("--test-filter")
    parser.add_argument("--acquisition-only",action="store_true",help="Focused fixed-container acquisition proof; reuse prior native/test evidence explicitly")
    args=parser.parse_args(); assert sum((args.tests_only,args.workers_only,args.acquisition_only))<=1
    c=Campaign(args.repo.resolve()); print(c.root,flush=True); result=dict(result="FAIL")
    try:
        c.prepare(); count=0 if args.workers_only or args.acquisition_only else c.tests(args.test_filter)
        if args.acquisition_only: c.acquisitions()
        elif not args.tests_only: c.workers()
        c.verify(); result=dict(result="PASS",tests=count,tests_executed=not (args.workers_only or args.acquisition_only),
            worker_cases=len(c.matrix),workers_executed=not args.tests_only,worker_scope="acquisition-only" if args.acquisition_only else "full",binaries=c.binaries)
    finally: c.finish(result)
    print(json.dumps(dict(result=result["result"],tests=result["tests"],worker_cases=result["worker_cases"],evidence=str(c.evidence))),flush=True)

if __name__=="__main__": main()
