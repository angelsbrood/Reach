#!/usr/bin/env python3
"""S88 offline actual-wire/native fixture. Prior implementations are copied unchanged."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
PRODUCT = Path(__file__).resolve().parent
SOURCE = PRODUCT.parents[1]
GIB = 1 << 30
EXCEPTIONS = {"ReachKit/Sources/ReachWire/DurableNegotiation.swift", "ReachKit/Tests/ReachWireTests/DurableWireTests.swift", "docs/wire.md"}
S86_SHA = "8f8cbc413ab2f279661953e6d65edbecbc3f189c67a048838b821234c78dd638"
S87_INVENTORY = Path("/private/tmp/reach-s87-correction.m65ixdam/evidence/final-bindings.json")
S87_INVENTORY_SHA = "f37f4530298c560e975421868360eab6d97fe1571a058133e54a42ff10c6e57e"

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def save(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def source(repo,path): return SOURCE/path if (SOURCE/path).is_file() else repo/path

def payload(frame,kind):
    assert len(frame)>=5 and struct.unpack(">I",frame[:4])[0]==len(frame)-4 and frame[4]==kind
    return json.loads(frame[5:])

def changed(frame,kind,edit):
    value=payload(frame,kind);edit(value);body=bytes([kind])+encoded(value)
    return struct.pack(">I",len(body))+body

def digest(domain,context,parts):
    h=hashlib.sha256()
    for data in [b"S84/v1/"+domain.encode(),context,*parts]:h.update(struct.pack(">Q",len(data)));h.update(data)
    return h.hexdigest()

class Scenario:
    """Supervisor sees frames as comparison oracles, never recovery entry seeds."""
    def __init__(self,c,label,route):
        self.c=c;self.label=label;self.route=route;self.root=c.fixtures/label
        self.host=c.worker("HostWireWorker",self.config(setup=True,host=True),label+"-host")
        assert self.host.ready["action"]=="ready",self.host.ready
        assert self.host.ready["keyCreates"]==3 and self.host.ready["keyLoads"]==2
        self.identity={k:self.host.ready[k] for k in ("bootstrapID","hostID","clientID","boot")}
        self.sidecar=c.fixtures/("tickets-"+self.identity["bootstrapID"])
        self.client=c.worker("ClientWireWorker",self.config(setup=True),label+"-client");self.check(self.client,"client")
        self.frames=[];self.receipts=[];self.high=0;self.terminal=False;self.calls=0;self.effects=0
        self.capabilities()
        self.opened=self.roundtrip("open",52);self.accepted=self.roundtrip("begin",54,route=route)
        self.original=payload(self.accepted,54);self.context=base64.b64decode(self.original["context"],validate=True)
        self.reference=self.original["reference"];self.ticket=payload(self.opened,52)["ticket"]
    def config(self,setup=False,host=False):
        config=dict(action="setup" if setup else "recover",root=str(self.root),optIn=True,fresh=setup,
            caller=dict(principal="s88-alice",device="s88-device",app="s88-app"),allowed=True,
            dialect=2,model="s88-tiny-native",profile="reach-durable-session-v1")
        if setup and host:config.update(container=str(self.c.fixtures/"containers/primary.keychain-db"),workers=self.c.worker_bindings)
        if not setup:assert not {"ticket","context","password","workers","container","route","request","result"}.intersection(config)
        return config
    def check(self,worker,role):
        assert worker.ready["action"]=="ready",worker.ready
        assert all(worker.ready[k]==v for k,v in self.identity.items())
        assert worker.ready["keyCreates"]==0 and worker.ready["keyLoads"]==(2 if role=="host" else 1)
        assert worker.ready["seedFieldsAbsent"]
    def capabilities(self):
        frames,result=self.host.exchange("capabilities");assert result["action"]=="ok" and len(frames)==1
        payload(frames[0],50);assert self.client.wire(frames[0],fragmented=True)[1]["action"]=="handled"
    def route_to_host(self,frames,kind):
        assert len(frames)==1
        replies,state=self.host.wire(frames[0]);assert state["action"]=="handled" and len(replies)==1,state
        payload(replies[0],kind);assert self.client.wire(replies[0])[1]["action"]=="handled"
        return replies[0],state
    def roundtrip(self,action,kind,**fields):
        frames,result=self.client.exchange(action,**fields);assert result["action"]=="ok",result
        return self.route_to_host(frames,kind)[0]
    def receipt(self,retry=False):
        frames,result=self.client.exchange("retry-receipt" if retry else "receipt");assert result["action"]=="ok",result
        w=payload(frames[0],57)["witness"];self.verify_witness(w)
        ack,state=self.route_to_host(frames,58);assert payload(ack,58)["witness"]==w
        self.receipts.append(w);self.last_receipt=frames[0];self.last_ack=ack
        return state
    def drain(self):
        frames,result=self.host.exchange("replay");assert result["action"]=="ok",result
        for frame in frames:
            p=payload(frame,56);assert p["reference"]==self.reference and p["contextDigest"]==self.original["contextDigest"]
            assert p["first"]==self.high+1 and p["skip"]==0
            data=base64.b64decode(p["bytes"],validate=True);events=json.loads(data);assert len(events)==p["count"]
            reply=self.client.wire(frame)[1];assert reply["action"]=="handled",reply
            self.high+=p["count"];assert reply["high"]==self.high;self.terminal=reply["terminal"];self.frames.append(p)
    def step(self):
        self.receipt();frames,result=self.host.exchange("step");assert not frames and result["action"]=="ok",result
        self.calls=result["calls"];assert result["prefills"]==0
        self.drain()
    def drive(self):
        for _ in range(600):
            if self.terminal:return
            self.step()
        raise AssertionError("bounded native continuation")
    def batches(self):return [{k:p[k] for k in ("first","count","commit","skip","bytes")} for p in self.frames]
    def events(self):return [e for p in self.frames for e in json.loads(base64.b64decode(p["bytes"],validate=True))]
    def verify_witness(self,w):
        assert w["context"]==hashlib.sha256(self.context).hexdigest() and w["clientRoot"]==self.identity["clientID"]
        assert w["high"]==self.high and w["terminal"]==self.terminal
        assert (w["revision"]==0 if not self.frames else w["revision"]>0)
        parts=[]
        for p in self.frames:parts += [struct.pack(">Q",p["first"]),struct.pack(">Q",p["count"]),p["commit"].encode(),base64.b64decode(p["bytes"],validate=True)]
        parts.append(struct.pack(">Q",len(self.frames)))
        assert w["prefix"]==digest("full-prefix",self.context,parts)
        calls=[e["toolCallAppendArguments"] for e in self.events() if "toolCallAppendArguments" in e]
        call_parts=[]
        for call in calls:call_parts += [call["id"].encode(),call["name"].encode(),call["content"].encode()]
        call_parts.append(struct.pack(">Q",len(calls)))
        assert w["registrations"]==len(calls) and w["calls"]==digest("ordered-calls",self.context,call_parts)
    def fresh_client(self,reattach=True):
        self.client=self.c.worker("ClientWireWorker",self.config(),self.label+"-fresh-client");self.check(self.client,"client")
        if reattach:self.attach()
    def attach(self):
        self.capabilities();frames,result=self.client.exchange("recover")
        assert result["action"]=="ok" and result["origin"]=="selected-client-record-and-ticket-envelope" and result["phase"]=="recovering",result
        recovered=payload(frames[0],55)
        # First read the newly recovered wire value, then compare it with supervisor oracles.
        assert recovered["ticket"]==self.ticket and recovered["context"]==self.original["context"]
        assert recovered["reference"]==self.reference and recovered["contextDigest"]==self.original["contextDigest"]
        assert recovered["witness"]==self.receipts[-1]
        reply,_=self.route_to_host(frames,54);p=payload(reply,54)
        assert p["kind"]=="recover" and p["context"]==self.original["context"] and p["reference"]==self.reference
    def retire(self):
        assert self.terminal and self.calls>0
        state=self.receipt();assert state["phase"]=="tombstone" and state["disposition"].startswith("durable-receipt-v1:")
        assert state["disposition"]=="durable-receipt-v1:"+digest("receipt-disposition",b"",[encoded(self.receipts[-1])])
        original=self.last_receipt;ack=self.last_ack;assert self.receipt(retry=True)["phase"]=="tombstone"
        assert self.last_receipt==original and self.last_ack==ack
        altered=changed(original,57,lambda p:p["witness"].update(prefix="f"*64))
        frames,result=self.host.wire(altered);assert result["action"]=="handled" and len(frames)==1
        assert payload(frames[0],60)["correlation"]["operation"]=="receipt"
        assert not any((self.root/"host/children").iterdir()) and not any((self.root/"host/requests").iterdir())
    def close(self):
        for worker in (self.client,self.host):
            if worker.p.poll() is None:worker.close()
        for path in (self.root,self.sidecar):
            if path.exists():shutil.rmtree(path)

def classes(repo):
    prior=repo/"Tools/DurableSessionDiscovery/run.py"
    assert sha(prior)==S86_SHA
    accepted=runpy.run_path(str(prior)) # Reuse bounded command/archive/cleanup helpers, never old campaigns/prepare.
    Base,BaseWorker=accepted["Campaign"],accepted["Worker"]

    class Worker(BaseWorker):
        def read(self):
            h=self.exact(5);assert h[0] in (0,1)
            size=struct.unpack(">I",h[1:])[0];assert 0<size<=((16<<20)+4 if h[0] else 2<<20)
            data=self.exact(size)
            if h[0]: return data
            value=json.loads(data);assert encoded(value)==data
            if "peak" in value:
                assert value["peak"]<=128<<20;self.c.mlx_peak=max(self.c.mlx_peak,value["peak"])
            return value
        def replies(self):
            frames=[]
            while True:
                value=self.read()
                if isinstance(value,dict): return frames,value
                frames.append(value);assert len(frames)<=4096 and sum(map(len,frames))<=32<<20
        def exchange(self,action,**fields):
            self.send(dict(action=action,**fields));return self.replies()
        def wire(self,data,fragmented=False):
            frames=[];last=None
            width=7 if fragmented else (16<<20)+4
            for start in range(0,len(data),width):
                chunk=data[start:start+width]
                packet=b"\1"+struct.pack(">I",len(chunk))+chunk
                rest=memoryview(packet)
                while rest:
                    n=os.write(self.p.stdin.fileno(),rest[:65536]);assert n>0;rest=rest[n:]
                reply,last=self.replies();frames+=reply
                assert last["action"] in ("handled","refused")
            return frames,last

    class Campaign(Base):
        def __init__(self,repo):
            os.umask(0o077);self.repo=repo
            self.root=Path(tempfile.mkdtemp(prefix="reach-durable-session-wire-adapters.",dir="/private/tmp"))
            self.private=self.root/"private";self.logs=self.root/"logs";self.evidence=self.root/"evidence"
            for p in (self.private,self.logs,self.evidence):p.mkdir()
            self.package=self.private/"harness";self.package.mkdir()
            self.fixtures=self.private/"fixtures";self.fixtures.mkdir();(self.fixtures/"containers").mkdir()
            self.env=dict(os.environ,S88_FIXTURES=str(self.fixtures),CLANG_MODULE_CACHE_PATH=str(self.private/"clang-cache"),SWIFTPM_MODULECACHE_OVERRIDE=str(self.private/"swift-cache"))
            self.commands=[];self.children=[];self.worker_objects=[];self.observations=[];self.matrix=[]
            self.mlx_peak=0;self.controller=None;self.container_cleanup=None;self.passwords={};self.sample();self.child_record()
        def sample(self):
            def allocated(root):return sum(p.lstat().st_blocks*512 for p in [root,*root.rglob("*")] if p.exists())
            total=allocated(self.root)
            if str(SOURCE).startswith("/private/tmp/reach-s88."):total+=allocated(SOURCE.parent)
            fixtures=allocated(self.fixtures);containers=allocated(self.fixtures/"containers");free=shutil.disk_usage(self.root).free
            assert total<=16*GIB and fixtures<=3*GIB and containers<=64<<20 and free>=20*GIB
            assert all(p.stat().st_size<=192<<20 for folder in [self.logs,self.evidence] for p in folder.rglob("*") if p.is_file())
            self.observations.append(dict(allocated=total,fixtures=fixtures,containers=containers,free=free))
        def prepare(self):
            assert sha(S87_INVENTORY)==S87_INVENTORY_SHA
            inventory=json.loads(S87_INVENTORY.read_text());baseline=inventory["unchanged_S86_bindings"]|inventory["products"]
            assert len(baseline)==181
            self.inputs={p:h for p,h in baseline.items() if p not in EXCEPTIONS}
            assert len(self.inputs)==178 and sum(p.startswith("Tools/") for p in self.inputs)==160
            for p,h in self.inputs.items():assert sha(self.repo/p)==h and not (self.repo/p).is_symlink(),p
            products={str(p.relative_to(PRODUCT)):sha(p) for p in PRODUCT.rglob("*") if p.is_file()}
            assert len(products)==15 and not any(p.is_symlink() for p in PRODUCT.rglob("*"))
            legacy=runpy.run_path(str(self.repo/"Tools/DurableSessionLifecycle/run.py"))
            assert sha(self.repo/legacy["METALLIB"])==legacy["METALLIB_SHA"]
            wire={str(p.relative_to(self.repo)):sha(source(self.repo,str(p.relative_to(self.repo)))) for p in (self.repo/"ReachKit/Sources/ReachWire").glob("*.swift")}
            assert len(wire)==9
            save(self.evidence/"inputs.json",dict(baseline_inventory_sha256=S87_INVENTORY_SHA,unchanged=self.inputs,products=products,wire_sources=wire,
                bounded_existing_edits={p:sha(source(self.repo,p)) for p in EXCEPTIONS},pins=legacy["PINS"],metallib_sha256=legacy["METALLIB_SHA"]))
            revisions={}
            for name,revision in legacy["PINS"].items():self.export(self.repo/"reachd/.build/checkouts"/name,self.package/name if name=="mlx-swift-lm" else self.private/name,revision,revisions)
            manifest=self.private/"mlx-swift/Package.swift";text=manifest.read_text()
            for name in ("swift-numerics","swift-argument-parser"):
                old=f'.package(url: "https://github.com/apple/{name}", from: "1.0.0")';assert text.count(old)==1;text=text.replace(old,f'.package(path: "../{name}")')
            manifest.write_text(text)
            lm=self.package/"mlx-swift-lm"
            for n,name in enumerate(legacy["PREREQUISITES"]):
                if "mlx-swift-lm.patch" in legacy["PREREQUISITES"][name]:
                    patch=self.repo/"Tools"/name/"mlx-swift-lm.patch"
                    self.command(["git","apply","--check",str(patch)],f"patch-check-{n}",lm);self.command(["git","apply",str(patch)],f"patch-apply-{n}",lm)
            self.outputs={p:sha(lm/p) for p in legacy["PRIOR_OUTPUTS"]};assert self.outputs==legacy["PRIOR_OUTPUTS"] and len(self.outputs)==35
            self.revisions=revisions
            save(self.evidence/"composition.json",dict(revisions=revisions,unchanged_native_outputs=self.outputs,new_native_outputs=0))
            pairs=[("ResumableRequiredToolCoordinator","RequiredToolCoordinator"),("ResumableAllowedToolCoordinator","AllowedToolCoordinator"),
                ("ResumableMLXProvider","ResumableMLXProvider"),("DurableHostStore","DurableHostStore"),
                ("DurableSessionLifecycle","DurableSessionLifecycle"),("DurableSessionLifecycle","LifecycleFixtures"),("DurableClientReceipts","DurableClientReceipts"),
                *[("DurableHostClientIntegration",m) for m in ("DurableClientReceipts","DurableSessionLifecycle","HostClientContract")],
                *[("DurableStoreBootstrap",m) for m in ("DurableRootKeys","DurableStoreBootstrap")],
                *[("DurableSessionDiscovery",m) for m in ("DurableClientReceipts","RecoveryContract")]]
            copied={}
            def copy(src,dest):
                assert not dest.exists();dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest);copied[str(dest.relative_to(self.package))]=sha(src)
            for folder,module in pairs:
                for src in (self.repo/"Tools"/folder/"Sources"/module).glob("*.swift"):copy(src,self.package/"Sources"/module/src.name)
            for p in wire:copy(source(self.repo,p),self.package/"Sources/ReachWire"/Path(p).name)
            for p in ("LLMModel.swift","Models/Llama.swift"):copy(lm/"Libraries/MLXLLM"/p,self.package/"TinyLlama"/Path(p).name)
            for name in products:
                if name.startswith(("Sources/","Tests/")) or name=="Package.swift":copy(PRODUCT/name,self.package/name)
            p="ReachKit/Tests/ReachWireTests/DurableWireTests.swift";copy(source(self.repo,p),self.package/"Tests/ReachWireTests/DurableWireTests.swift")
            self.copied=copied;save(self.evidence/"copied-libraries.json",copied)
            self.flags=["--package-path",str(self.package),"--scratch-path",str(self.private/"build"),"--cache-path",str(self.private/"spm-cache"),
                "--config-path",str(self.private/"spm-config"),"--security-path",str(self.private/"spm-security"),"--disable-sandbox","--disable-netrc","--disable-keychain",
                "--disable-dependency-cache","--disable-prefetching","--skip-update","--disable-index-store","--build-system","native","--jobs","4"]
            output=self.command(["xcrun","swift","build",*self.flags,"--show-bin-path"],"binary-path")
            paths=[p for p in output.splitlines() if p.startswith(str(self.private/"build")+"/")];assert len(paths)==1
            self.binary=Path(paths[0]);self.binary.mkdir(parents=True,exist_ok=True)
            shutil.copy2(self.repo/legacy["METALLIB"] ,self.binary/"mlx.metallib");shutil.copy2(self.repo/legacy["METALLIB"],self.package/"default.metallib")
            self.command(["xcrun","swift","build",*self.flags,"--build-tests"],"build")
            for bundle in (self.private/"build").rglob("*.xctest"):
                target=bundle/"Contents/MacOS";target.mkdir(parents=True,exist_ok=True);shutil.copy2(self.repo/legacy["METALLIB"],target/"mlx.metallib")
            names=["HostWireWorker","ClientWireWorker","KeychainWorker"]
            self.binaries={name:sha(self.binary/name) for name in names};self.worker_bindings=[dict(path=str(self.binary/name),sha256=self.binaries[name]) for name in names]
            for name in names[1:]:
                symbols=self.command(["nm",str(self.binary/name)],"cpu-symbols-"+name)
                assert not re.search(r"(?i)(mlx_|cmlx|\$s\d+MLX|_ZN3mlx)",symbols)
        def tests(self):
            log=self.command(["xcrun","swift","test",*self.flags,"--skip-build","--no-parallel"],"tests")
            # SwiftPM stderr can split a buffered XCTest/Testing stdout line.
            # Remove only this exact known CLI diagnostic for parsing; retain
            # the original log, command exit status and diagnostic count.
            diagnostic="warning: '--build-system native' has been deprecated and will be removed in a future release; please report an issue at https://github.com/swiftlang/swift-package-manager/issues if you are unable to adopt the default build system.\n"
            diagnostic_count=log.count(diagnostic);log=log.replace(diagnostic,"")
            selected=sorted(re.findall(r"func (test\w+)\(","\n".join(p.read_text() for p in (PRODUCT/"Tests").rglob("*.swift"))))
            started=sorted(re.findall(r"Test Case '-\[DurableSessionWireAdapterTests\.\w+ (test\w+)\]' started",log))
            passed=sorted(re.findall(r"Test Case '-\[DurableSessionWireAdapterTests\.\w+ (test\w+)\]' passed",log))
            assert selected==started==passed and passed
            wire=sorted(re.findall(r"@Test func (\w+)\(",source(self.repo,"ReachKit/Tests/ReachWireTests/DurableWireTests.swift").read_text()))
            wire_passed=sorted(re.findall(r"Test (\w+)\(\) passed after",log));assert wire==wire_passed
            save(self.evidence/"tests.json",dict(adapter_selected=selected,adapter_started=started,adapter_passed=passed,wire_selected=wire,wire_passed=wire_passed,known_cli_diagnostics_removed_for_parsing=diagnostic_count));return len(passed)+len(wire)
        def worker(self,name,config,label):return Worker(self,self.binary/name,config,label+"-"+str(len(self.children)))
        def workers(self):
            for name in ("HostWireWorker","ClientWireWorker"):
                w=self.worker(name,dict(action="setup"),"default-off");assert w.ready==dict(action="disabled",keyCreates=0,keyLoads=0);w.join()
                for version in (0,1):
                    w=self.worker(name,dict(action="setup",optIn=True,dialect=version),"old-dialect")
                    assert w.ready["action"]=="unavailable";w.join(expected=1)
            self.record("worker-entry-gates",default_off_zero_keys=True,v0_v1_before_root_and_keys=True)
            self.controller=self.worker("KeychainWorker",dict(action="control",workers=self.worker_bindings),"keychain-controller")
            assert self.controller.ready["action"]=="ready",self.controller.ready
            self.passwords["primary"]=uuid.uuid4().hex+uuid.uuid4().hex
            created=self.controller.request("create",slot="primary",password=self.passwords["primary"])
            assert created["action"]=="ok" and created["metadataPreserved"],created
            reference=Scenario(self,"ordinary-reference","ordinary")
            try:
                reference.drive();reference.retire()
                expected=reference.batches();expected_events=reference.events()
                save(self.private/"ordinary-oracle.json",dict(batches=expected,events=expected_events))
                # The recovery run must make new native calls before reading this oracle.
                del expected,expected_events
            finally:reference.close()
            active=Scenario(self,"ordinary-recovery","ordinary")
            try:
                for _ in range(600):
                    active.step()
                    if active.high>0:break
                assert active.high>0 and not active.terminal and active.calls>0
                active.receipt();prefix=active.batches();original_witness=active.receipts[-1]
                host_pid=active.host.p.pid;client_pid=active.client.p.pid
                active.host.join(killed=True);active.client.close()
                active.host=self.worker("HostWireWorker",active.config(),"ordinary-fresh-host");active.check(active.host,"host")
                active.calls=0;active.fresh_client();assert active.receipts[-1]==original_witness
                active.drain();active.step();assert active.calls>0
                active.drive();assert active.batches()[:len(prefix)]==prefix
                counters=active.host.exchange("inspect")[1]
                assert counters["issues"]==0 and counters["begins"]==0 and counters["recoveries"]==1 and counters["prefills"]==0
                oracle=json.loads((self.private/"ordinary-oracle.json").read_text())
                assert active.batches()==oracle["batches"] and active.events()==oracle["events"]
                active.retire()
                self.record("ordinary-native-wire-recovery",prefix_batches=len(prefix),prefix_events=original_witness["high"],
                    active_host_killed_joined=host_pid,original_client_ended_joined=client_pid,new_native_calls=active.calls,
                    exact_complete_batch_bytes_and_commits=True,exact_events=True,original_ticket_context_reference=True,
                    exact_original_witness_on_recovery=True,exact_context_bound_receipts_and_retry=True,
                    identity_note="Independent reference roots have distinct context/clientRoot and context-bound receipt digests; each full witness is independently recomputed from exact original context and batches.",
                    entry_fields=sorted(active.config()),recovery_seeds_absent=True,new_open_begin=False,prefill_calls=0)
            finally:active.close()
            tool=Scenario(self,"required-knowledge","required")
            try:
                tool.drive();assert len(tool.frames)==1 and tool.terminal
                assert tool.client.exchange("local-state")[1]["state"]=="unbegun"
                assert tool.client.exchange("knowledge")[1]["action"]=="refused"
                frames,permission=tool.client.exchange("effect");assert not frames and permission["action"]=="fake-effect"
                tool.effects+=1;completion=base64.b64encode(b"s88-counted-local-effect-result").decode()
                # Save the exact terminal witness without sending it: host history must remain for report validation.
                frames,result=tool.client.exchange("receipt");assert result["action"]=="ok"
                tool.receipts.append(payload(frames[0],57)["witness"]);tool.verify_witness(tool.receipts[-1])
                tool.client.close();tool.fresh_client()
                assert tool.client.exchange("local-state")[1]["state"]=="unknown"
                unknown,reply=tool.client.exchange("knowledge");assert reply["action"]=="ok" and len(unknown)==1
                assert payload(unknown[0],59)["state"]=="unknown" and "outcome" not in payload(unknown[0],59)
                assert tool.host.wire(unknown[0])[1]["action"]=="handled"
                assert tool.client.wire(unknown[0])[1]["action"]=="handled"
                assert tool.client.exchange("effect")[1]["state"]=="unknown"
                assert tool.client.exchange("record-local",result=completion)[1]["action"]=="ok"
                tool.client.close();tool.fresh_client()
                known,reply=tool.client.exchange("knowledge");assert reply["action"]=="ok" and len(known)==1
                value=payload(known[0],59);assert value["state"]=="known" and value["outcome"]["result"]==completion
                assert tool.host.wire(known[0])[1]["action"]=="handled" and tool.client.wire(known[0])[1]["action"]=="handled"
                assert tool.client.wire(unknown[0])[1]["action"]=="handled" # read-only unknown cannot overwrite known
                for edit in (lambda p:p.update(callID=base64.b64encode(b"wrong-call").decode()),lambda p:p.update(contextDigest="f"*64),
                             lambda p:p["outcome"].update(result=base64.b64encode(b"wrong-result").decode())):
                    bad=changed(known[0],59,edit)
                    assert tool.host.wire(bad)[1]["action"]=="refused" and tool.client.wire(bad)[1]["action"]=="refused"
                again=tool.client.exchange("knowledge")[0];assert again==known
                retry=tool.client.exchange("effect")[1];assert retry["state"]=="known" and retry["result"]==completion and tool.effects==1
                tool.retire();tool.host.close();tool.client.close();tool.fresh_client(reattach=False)
                independent=tool.client.exchange("local-state")[1];assert independent["state"]=="known" and independent["result"]==completion
                self.record("required-wire-knowledge-and-independent-retirement",native_calls=tool.calls,final_batches=1,registered_calls=1,
                    fresh_local_permission=1,counted_fake_effects=tool.effects,unknown_then_exact_known_across_reopen=True,
                    known_unknown_frames_checked_read_only=True,changed_call_context_outcome_refused=True,exact_known_report_retry=True,
                    receipt_retirement_and_exact_retry=True,known_survives_host_retirement=True,peer_report_execution_attestation=False)
            finally:tool.close()
            cleanup=self.controller.request("cleanup")
            assert cleanup["action"]=="ok" and cleanup["metadataPreserved"] and cleanup["registrationAbsent"]
            assert not any((self.fixtures/"containers").iterdir())
            self.record("scoped-keychain-cleanup",created_items=9,containers=1,host_acquires=2,client_acquires=1,
                frozen_S88_worker_access=True,root_keys_never_cross_workers=True,original_container_reference_deleted=True,
                unrelated_metadata_preserved=True,registrations_absent=True)
    return Campaign

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",type=Path,default=SOURCE);parser.add_argument("--tests-only",action="store_true")
    args=parser.parse_args();repo=args.repo.resolve();Campaign=classes(repo);c=Campaign(repo);print(c.root,flush=True)
    result=dict(result="FAIL")
    try:
        c.prepare();count=c.tests()
        if not args.tests_only:c.workers()
        c.verify();result=dict(result="PASS",tests=count,workers_executed=not args.tests_only,worker_cases=len(c.matrix),binaries=c.binaries)
    finally:c.finish(result)
    print(json.dumps(dict(result=result["result"],tests=result.get("tests"),evidence=str(c.evidence))),flush=True)

if __name__=="__main__":main()
