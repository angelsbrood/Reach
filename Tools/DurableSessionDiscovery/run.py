#!/usr/bin/env python3
"""S86 offline bootstrap/key candidate. No root keys cross the surviving supervisor."""
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
INPUTS_SHA = "fb288d7f3cb644e54acbbc45bc87d5c19899ad796aab2770df8259cbc8901b29"
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
        campaign.children.append(self.p); campaign.worker_objects.append(self); campaign.child_record()
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

def current_caller(): return dict(principal="s86-alice",device="s86-device",app="s86-app")

class RecoveryScenario:
    def __init__(self,campaign,label,register=True,knowledge=False):
        self.c=campaign; self.label=label; self.root=campaign.fixtures/label; self.generation="g-1"
        self.host=self.c.worker("HostRecoveryWorker",dict(action="setup",root=str(self.root),optIn=True,fresh=True,
            caller=current_caller(),container=str(campaign.fixtures/"containers/primary.keychain-db"),workers=campaign.worker_bindings),label+"-setup-host")
        assert self.host.ready["action"]=="ready" and self.host.ready["keyCreates"]==3 and self.host.ready["keyLoads"]==2
        self.identity={k:self.host.ready[k] for k in ("bootstrapID","hostID","clientID","boot")}
        self.sidecar=campaign.fixtures/("tickets-"+self.identity["bootstrapID"])
        issued=self.host.request("issue"); assert issued["action"]=="ok"
        begun=self.host.request("begin",generation=self.generation,route="ordinary"); assert begun["action"]=="ok"
        # Private expected-value oracles, never inputs to the recovery entry/dispatch below.
        self.oracle_ticket=issued["ticket"]; self.oracle_context=begun["context"]
        self.client=self.c.worker("ClientRecoveryWorker",dict(action="setup",root=str(self.root),optIn=True,fresh=True,
            caller=current_caller(),ticket=issued["ticket"],context=begun["context"]),label+"-setup-client")
        self.check_identity(self.client,"client"); self.witness=self.client.ready["witness"]
        self.frames=[]; self.native_calls=0; self.effects=0
        if knowledge:
            assert self.client.request("seed-knowledge")["action"]=="fake-effect"; self.effects+=1
            self.client.send(dict(action="effect-recorded")); reply=self.client.read(); assert reply["action"]=="ok" and reply["calls"]==2
        if register: assert self.client.request("register")["state"]=="recovery-ready"
    def check_identity(self,worker,role):
        assert worker.ready["action"]=="ready",{k:v for k,v in worker.ready.items() if k in ("action","stage","code")}
        assert all(worker.ready[k]==v for k,v in self.identity.items())
        assert worker.ready["keyCreates"]==0 and worker.ready["keyLoads"]==(2 if role=="host" else 1)
    def recovery_config(self):
        config=dict(action="recover",root=str(self.root),optIn=True,fresh=False,caller=current_caller(),allowed=True)
        assert not {"ticket","context","password","workers","key","metadataKey","ticketKey"}.intersection(config)
        return config
    def fresh_client(self):
        config=self.recovery_config()
        worker=self.c.worker("ClientRecoveryWorker",config,self.label+"-fresh-client")
        self.check_identity(worker,"client")
        assert worker.ready["seedFieldsAbsent"] and worker.ready["origin"]=="selected-client-manifest"
        return worker
    def native_selection(self):
        response=self.client.request("discover"); assert response["action"]=="ok"
        native=[s for s in response["summaries"] if s["calls"]==0]; assert len(native)==1; return native[0]
    def disk_join(self):
        selected=self.native_selection()
        result=self.client.request("resolve",selection=selected)
        assert result["action"]=="ok" and result["origin"]=="selected-client-snapshot"
        recovered=self.client.request("recover-ticket")
        assert recovered["action"]=="ok" and recovered["origin"]=="selected-client-record-and-ticket-envelope"
        assert recovered["context"]==self.oracle_context and recovered["ticket"]==self.oracle_ticket
        assert recovered["generation"]==self.generation and recovered["route"]=="ordinary"
        return recovered
    def reattach_from_disk(self):
        self.client=self.fresh_client(); recovered=self.disk_join()
        self.witness=recovered["witness"]
        self.host=self.c.worker("HostRecoveryWorker",self.recovery_config(),self.label+"-fresh-host")
        self.check_identity(self.host,"host"); assert self.host.ready["seedFieldsAbsent"]
        # Only this newly recovered reply supplies the host attachment credentials.
        routed={k:recovered[k] for k in ("ticket","context","witness","generation","route","origin")}
        attached=self.host.request("attach-recovered",**routed)
        assert attached["action"]=="ok" and attached["context"]==recovered["context"]
        self.native_calls=0
        self.c.record("fresh-recovery-origin",client_entry_fields=sorted(self.recovery_config()),host_entry_fields=sorted(self.recovery_config()),
            seed_fields_absent=True,exact_original_ticket_context=True,original_ids=True,recovered_source=recovered["origin"],pre_crash_credentials_used_as_recovery_input=False)
    def receipt(self): return self.host.request("receipt",generation=self.generation,witness=self.witness)
    def drain(self):
        cursor=self.witness["high"]; self.host.send(dict(action="replay",cursor=cursor))
        while True:
            reply=self.host.read()
            if reply["action"]=="replay-end": return
            assert reply["action"]=="batch"; self.frames.append(reply["frame"])
            accepted=self.client.request("accept",frame=reply["frame"],cursor=cursor); assert accepted["action"]=="ok"
            self.witness=accepted["witness"]; self.host.send(dict(action="next"))
    def step(self):
        assert self.receipt()["action"]=="ok"
        reply=self.host.request("step"); assert reply["action"]=="ok"
        self.native_calls=max(self.native_calls,reply["calls"]); self.drain()
    def drive(self):
        for _ in range(600):
            if self.witness["terminal"]: return
            self.step()
        raise AssertionError("bounded native continuation")
    def events(self):
        high=0; result=[]
        for frame in self.frames:
            assert frame["first"]==high+1 and frame["skip"]==0
            batch=json.loads(base64.b64decode(frame["bytes"],validate=True)); assert len(batch)==frame["count"]
            result.extend(batch); high+=len(batch)
        assert high==self.witness["high"]; return result
    def retire(self):
        assert self.host.request("validate")["action"]=="ok" and self.native_calls>0 and self.witness["terminal"]
        result=self.receipt(); assert result["action"]=="ok" and result["phase"]=="tombstone"
        assert result["terminal"] and result["high"]==self.witness["high"] and result["disposition"].startswith("durable-receipt-v1:")
        assert not any((self.root/"host/children").iterdir()) and not any((self.root/"host/requests").iterdir())
        assert self.client.request("witness")["witness"]==self.witness
    def close(self):
        for worker in (self.client,self.host):
            if worker.p.poll() is None: worker.close()
        for path in (self.root,self.sidecar):
            if path.exists(): shutil.rmtree(path)

class Campaign:
    def __init__(self,repo):
        os.umask(0o077); self.repo=repo
        self.root=Path(tempfile.mkdtemp(prefix="reach-durable-session-discovery.",dir="/private/tmp"))
        self.private=self.root/"private"; self.logs=self.root/"logs"; self.evidence=self.root/"evidence"
        for p in (self.private,self.logs,self.evidence): p.mkdir()
        self.package=self.private/"harness"; self.package.mkdir()
        self.fixtures=self.private/"fixtures"; self.fixtures.mkdir(); (self.fixtures/"containers").mkdir()
        self.env=dict(os.environ,S86_FIXTURES=str(self.fixtures),CLANG_MODULE_CACHE_PATH=str(self.private/"clang-cache"),
            SWIFTPM_MODULECACHE_OVERRIDE=str(self.private/"swift-cache"))
        self.commands=[]; self.children=[]; self.worker_objects=[]; self.observations=[]; self.matrix=[]
        self.mlx_peak=0; self.controller=None; self.container_cleanup=None; self.passwords={}; self.sample(); self.child_record()
    def child_record(self):
        save(self.evidence/"owned-pids.json",dict(supervisor=os.getpid(),children=[p.pid for p in self.children]))
    def sample(self):
        def allocation(root):
            total=0
            for p in [root,*root.rglob("*")]:
                try: total+=p.lstat().st_blocks*512
                except FileNotFoundError: pass
            return total
        allocated=allocation(self.root)
        if PRODUCT.parent.name.startswith("reach-s86."): allocated+=allocation(PRODUCT.parent)
        fixtures=allocation(self.fixtures); containers=allocation(self.fixtures/"containers"); free=shutil.disk_usage(self.root).free
        assert allocated<=16*GIB and fixtures<=3*GIB and containers<=64<<20 and free>=20*GIB,"S86 resource bounds"
        assert all(p.stat().st_size<=192<<20 for p in self.logs.rglob("*") if p.is_file())
        self.observations.append(dict(allocated=allocated,fixtures=fixtures,containers=containers,free=free))
    def command(self,args,label,cwd=None):
        self.sample(); log=self.logs/(label+".log"); start=time.monotonic()
        with log.open("wb") as output:
            p=subprocess.Popen(args,cwd=cwd or self.package,env=self.env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            self.children.append(p); self.child_record()
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
        folders=[*legacy["PREREQUISITES"],"DurableSessionLifecycle","DurableClientReceipts","DurableHostClientIntegration","DurableStoreBootstrap"]
        inputs={str(p.relative_to(self.repo)):sha(p) for folder in folders for p in (self.repo/"Tools"/folder).rglob("*") if p.is_file()}
        assert len(inputs)==140
        selected=[*legacy["SELECTED_SOURCES"],"ReachKit/Sources/ReachKit/ReachLanguageModel.swift","ReachKit/Sources/ReachWire/Frames.swift"]
        inputs.update({p:sha(self.repo/p) for p in selected})
        assert len(inputs)==154 and hashlib.sha256(encoded(inputs)).hexdigest()==INPUTS_SHA
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
            *[("DurableHostClientIntegration",m) for m in ("DurableClientReceipts","DurableSessionLifecycle","HostClientContract","HostClientFixtures")],
            *[("DurableStoreBootstrap",m) for m in ("DurableRootKeys","DurableStoreBootstrap")]]
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
        names=["HostRecoveryWorker","ClientRecoveryWorker","KeychainWorker"]
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
        started=sorted(re.findall(r"Test Case '-\[DurableSessionDiscoveryTests\.\w+ (test\w+)\]' started",log))
        passed=sorted(re.findall(r"Test Case '-\[DurableSessionDiscoveryTests\.\w+ (test\w+)\]' passed",log))
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
    def workers(self):
        for name in ("HostRecoveryWorker","ClientRecoveryWorker"):
            root=self.fixtures/("off-"+name.lower())
            worker=self.worker(name,dict(action="recover",root=str(root),optIn=False,fresh=False),"default-off")
            assert worker.ready==dict(action="disabled",keyCreates=0,keyLoads=0) and not root.exists(); worker.join()
        self.record("default-off",provider_accesses=0,journal_mutations=0)
        self.controller=self.worker("KeychainWorker",dict(action="control",workers=self.worker_bindings),"keychain-controller")
        assert self.controller.ready["action"]=="ready",{k:v for k,v in self.controller.ready.items() if k in ("action","stage","code")}
        self.passwords["primary"]=uuid.uuid4().hex+uuid.uuid4().hex
        created=self.controller.request("create",slot="primary",password=self.passwords["primary"])
        assert created["action"]=="ok" and created["metadataPreserved"]
        reference=RecoveryScenario(self,"ordinary-reference")
        try:
            reference.drive(); expected=reference.events(); reference.retire()
            self.record("ordinary-reference",native_calls=reference.native_calls,original_ticket_registered=True,receipt_retired=True)
        finally: reference.close()
        active=RecoveryScenario(self,"ordinary-recovery",register=False,knowledge=True)
        try:
            for _ in range(600):
                active.step()
                if active.witness["high"]>0: break
            frontier=active.witness["high"]; assert frontier>0 and not active.witness["terminal"]
            assert active.receipt()["action"]=="ok"
            assert active.host.request("step",boundary="afterStep")==dict(action="boundary",boundary="afterStep")
            active.host.join(killed=True)
            assert active.client.request("register",boundary="afterSelection")==dict(action="boundary",boundary="afterSelection")
            active.client.join(killed=True)
            self.record("original-application-deaths",host_boundary="afterStep",client_boundary="afterSelection",original_application_workers_joined=True,
                selected_ticket_reply_lost=True,synthetic_knowledge_records=2,fake_effect_count=active.effects)
            for name,role in (("HostRecoveryWorker","host"),("ClientRecoveryWorker","client")):
                before=sha(active.root/role/"current")
                self.unavailable(name,dict(active.recovery_config(),ticket=base64.b64encode(b"forbidden-seed").decode()),"recovery-seed-refusal")
                assert sha(active.root/role/"current")==before
            active.reattach_from_disk(); active.drain(); active.drive()
            actual=active.events(); assert active.native_calls>0 and actual[:frontier]==expected[:frontier] and actual[frontier:]==expected[frontier:]
            active.retire(); original_receipt=active.witness
            assert active.disk_join()["ticket"]==active.oracle_ticket,"client lifetime outlasts host content retirement"
            active.host.close(); active.client.close()
            self.record("native-continuation-and-retirement",new_native_calls=active.native_calls,exact_prefix_suffix=True,receipt_retired=True,
                original_ticket_retained_after_host_retirement=True,seeded_entries_refused_without_journal_mutation=True)
            descriptor=self.descriptor(active.root); core=descriptor["core"]; binding=self.binding(core)
            assert self.controller.request("delete",reference=core["keys"][0],binding=binding)["action"]=="ok"
            before=sha(active.root/"host/current")
            self.unavailable("HostRecoveryWorker",active.recovery_config(),"missing-host-key","scoped-load-only")
            assert sha(active.root/"host/current")==before
            # Exact owned sidecar disposal is an unavailability fixture, never normal recovery repair.
            shutil.rmtree(active.sidecar)
            active.client=active.fresh_client()
            summaries=active.client.ready["summaries"]; assert len(summaries)==3
            states=[]
            for selected in summaries:
                reply=active.client.request("resolve",selection=selected); assert reply["action"]=="ok"
                if selected["calls"]==0:
                    assert reply["witness"]==original_receipt
                    assert active.client.request("recover-ticket")["action"]=="refused"
                else:
                    state=active.client.request("state"); assert state["action"]=="ok" and state["state"] in ("known","unknown")
                    states.append(state["state"])
                    for action in ("begin","effect"):
                        retry=active.client.request(action); assert retry["action"]=="ok" and retry["state"]==state["state"]
                        if state["state"]=="known": assert base64.b64decode(retry["result"])==b"s86-known-result"
            assert sorted(states)==["known","unknown"] and active.effects==1 and not active.sidecar.exists()
            self.record("independent-client-knowledge",host_key_unavailable=True,ticket_directory_unavailable=True,original_receipt=True,
                known_exact=True,unknown_retained=True,fake_effect_count=active.effects,permission_reissued=False,missing_history_recreated=False)
        finally: active.close()
        cleanup=self.controller.request("cleanup")
        assert cleanup["action"]=="ok" and cleanup["metadataPreserved"] and cleanup["registrationAbsent"]
        assert not any((self.fixtures/"containers").iterdir())
        self.record("new-worker-keychain-and-cleanup",created_items=6,containers=1,independent_host_key_loads=2,independent_client_key_loads=1,
            no_root_keys_in_supervisor=True,files_absent=True,registrations_absent=True,unrelated_metadata_preserved=True)
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
    args=parser.parse_args(); assert not (args.tests_only and args.workers_only)
    c=Campaign(args.repo.resolve()); print(c.root,flush=True); result=dict(result="FAIL")
    try:
        c.prepare(); count=0 if args.workers_only else c.tests(args.test_filter)
        if not args.tests_only: c.workers()
        c.verify(); result=dict(result="PASS",tests=count,tests_executed=not (args.workers_only),
            worker_cases=len(c.matrix),workers_executed=not args.tests_only,worker_scope="full",binaries=c.binaries)
    finally: c.finish(result)
    print(json.dumps(dict(result=result["result"],tests=result["tests"],worker_cases=result["worker_cases"],evidence=str(c.evidence))),flush=True)

if __name__=="__main__": main()
