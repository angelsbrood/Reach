#!/usr/bin/env python3
"""S91 offline selected-allowed preparation; no Keychain or old worker campaign."""
import argparse, base64, hashlib, json, math, os, re, runpy, shutil, signal, sys, tempfile
from pathlib import Path
sys.dont_write_bytecode=True
PRODUCT=Path(__file__).resolve().parent
SOURCE=PRODUCT.parents[1]
INVENTORY=Path("/private/tmp/reach-s90.x3k079ga/evidence/final-bindings.json")
INVENTORY_SHA="ddd5d497587daab4b2ba161fbe57c67d9470a60b4729a798617d9fd5d0a69f45"
EXCEPTIONS={"Tools/DurableRequestPreparation/"+p for p in ["Sources/RequestPreparationContract/ModelDescriptor.swift","Sources/RequestPreparationContract/RequestPolicy.swift","Sources/DurableRequestPreparation/RequestPreparation.swift","Sources/DurableRequestPreparation/TranscriptPreparation.swift","Sources/RequestPreparationFixtures/Fixtures.swift","README.md"]}|{"docs/wire.md"}
GIB=1<<30
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
def source(repo,p):return SOURCE/p if (SOURCE/p).is_file() else repo/p

def campaign_class(repo):
    helper=repo/"Tools/DurableSessionDiscovery/run.py"
    assert sha(helper)=="8f8cbc413ab2f279661953e6d65edbecbc3f189c67a048838b821234c78dd638"
    return runpy.run_path(str(helper))["Campaign"]

def make_campaign(repo):
    class Campaign(campaign_class(repo)):
        def __init__(self):
            os.umask(0o077);self.repo=repo
            self.root=Path(tempfile.mkdtemp(prefix="reach-durable-allowed-tool-preparation.",dir="/private/tmp"))
            self.guard_root=Path(tempfile.mkdtemp(prefix="reach-durable-request-preparation.",dir="/private/tmp"))
            self.regression=Path(tempfile.mkdtemp(prefix="reach-durable-session-wire-adapters.",dir="/private/tmp"))
            self.private=self.root/"private";self.logs=self.root/"logs";self.evidence=self.root/"evidence"
            self.package=self.private/"harness";self.fixtures=self.guard_root/"private/fixtures"
            for p in (self.package,self.fixtures/"containers",self.logs,self.evidence,self.regression/"private/fixtures/containers"):p.mkdir(parents=True)
            self.env=dict(os.environ,S89_FIXTURES=str(self.fixtures),S88_FIXTURES=str(self.regression/"private/fixtures"),CLANG_MODULE_CACHE_PATH=str(self.private/"clang-cache"),SWIFTPM_MODULECACHE_OVERRIDE=str(self.private/"swift-cache"))
            self.commands=[];self.children=[];self.worker_objects=[];self.observations=[];self.matrix=[]
            self.mlx_peak=0;self.controller=None;self.container_cleanup=None;self.passwords={};self.sample();self.child_record()
        def sample(self):
            def allocated(root):
                total=0
                for p in [root,*root.rglob("*")]:
                    try:total+=p.lstat().st_blocks*512
                    except FileNotFoundError:pass
                return total
            roots=[self.root,self.regression,self.guard_root]
            if str(SOURCE).startswith("/private/tmp/reach-s91."):roots.append(SOURCE.parent)
            total=sum(allocated(p) for p in roots);fixtures=allocated(self.fixtures)+allocated(self.regression);free=shutil.disk_usage(self.root).free
            assert total<=16*GIB and fixtures<=3*GIB and free>=20*GIB
            assert all(p.stat().st_size<=192<<20 for folder in (self.logs,self.evidence) for p in folder.rglob("*") if p.is_file())
            self.observations.append(dict(allocated=total,fixtures=fixtures,containers=0,free=free))
        def prepare(self):
            assert sha(INVENTORY)==INVENTORY_SHA
            inventory=json.loads(INVENTORY.read_text()); baseline=inventory["unchanged_S89_bindings"]|inventory["products"]
            assert len(baseline)==215
            self.inputs={p:h for p,h in baseline.items() if p not in EXCEPTIONS}
            for p,h in self.inputs.items():assert sha(self.repo/p)==h and not (self.repo/p).is_symlink(),p
            products={str(p.relative_to(PRODUCT)):sha(p) for p in PRODUCT.rglob("*") if p.is_file()}
            assert len(products)<=7 and not any(p.is_symlink() for p in PRODUCT.rglob("*"))
            legacy=runpy.run_path(str(self.repo/"Tools/DurableSessionLifecycle/run.py"))
            assert sha(self.repo/legacy["METALLIB"])==legacy["METALLIB_SHA"]
            wire={str(p.relative_to(self.repo)):sha(source(self.repo,str(p.relative_to(self.repo)))) for p in (self.repo/"ReachKit/Sources/ReachWire").glob("*.swift")}
            assert len(wire)==9
            save(self.evidence/"inputs.json",dict(baseline_inventory_sha256=INVENTORY_SHA,unchanged=self.inputs,products=products,wire_sources=wire,
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
            for src in (self.repo/"Tools/DurableSessionWireAdapters").rglob("*.swift"):
                relative=src.relative_to(self.repo/"Tools/DurableSessionWireAdapters")
                if relative.parts[0] in ("Sources","Tests"):
                    copy(source(self.repo,str(src.relative_to(self.repo))),self.package/relative)
            for src in (self.repo/"Tools/DurableRequestPreparation").rglob("*.swift"):
                relative=src.relative_to(self.repo/"Tools/DurableRequestPreparation")
                if relative.parts[0] in ("Sources","Tests"):
                    copy(source(self.repo,str(src.relative_to(self.repo))),self.package/relative)
            for src in (self.repo/"Tools/DurableSchemaPreparation").rglob("*.swift"):
                relative=src.relative_to(self.repo/"Tools/DurableSchemaPreparation")
                if relative.parts[0] in ("Sources","Tests"):copy(src,self.package/relative)
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
            names=["AllowedPreparationWorker","ClientWireWorker"]
            self.binaries={name:sha(self.binary/name) for name in names};self.worker_bindings=[]
            for name in names[1:]:
                symbols=self.command(["nm",str(self.binary/name)],"cpu-symbols-"+name)
                assert not re.search(r"(?i)(mlx_|cmlx|\$s\d+MLX|_ZN3mlx)",symbols)
                assert "RequestPreparationContract" in symbols
                save(self.evidence/"client-linkage.json",dict(binary_sha256=self.binaries[name],portable_policy_symbols=True,native_symbols_absent=True,symbol_log_sha256=sha(self.logs/("cpu-symbols-"+name+".log"))))
        def tests(self):
            # All S89 tests share the changed contract/preparer/fixture initializer.
            # Only these two S88 cases depend on its preserved default/admission.
            old=["testDefaultAndIncompatibleAdaptersGateBeforeDispatch","testFirstBeginAcceptanceRejectsOtherSupportedRequest"]
            selection="DurableAllowedToolPreparationTests|DurableSchemaPreparationTests|DurableRequestPreparationTests|"+"|".join(old)
            log=self.command(["xcrun","swift","test",*self.flags,"--skip-build","--no-parallel","--filter",selection],"tests")
            diagnostic="warning: '--build-system native' has been deprecated and will be removed in a future release; please report an issue at https://github.com/swiftlang/swift-package-manager/issues if you are unable to adopt the default build system.\n"
            # SwiftPM can insert this known diagnostic inside a test-case line.
            log=log.replace(diagnostic,"")
            selected=sorted(old+re.findall(r"func (test\w+)\(","\n".join(p.read_text() for folder in ("DurableAllowedToolPreparationTests","DurableSchemaPreparationTests","DurableRequestPreparationTests") for p in (self.package/"Tests"/folder).glob("*.swift"))))
            started=sorted(re.findall(r"Test Case '-\[\w+\.\w+ (test\w+)\]' started",log))
            passed=sorted(re.findall(r"Test Case '-\[\w+\.\w+ (test\w+)\]' passed",log))
            assert selected==started==passed and passed,(selected,started,passed)
            save(self.evidence/"tests.json",dict(filter=selection,selected=selected,started=started,passed=passed))
            return len(passed)
        def workers(self):
            def run(mode,root,label,family,variant=None):
                output=self.fixtures/(label+".json")
                args=[str(self.binary/"AllowedPreparationWorker"),mode,str(root),str(output),family]
                if variant is not None:args.append(variant)
                self.command(args,label);return output
            def batches(s):return [{k:b[k] for k in ("first","count","commit","skip","bytes")} for b in s["batches"]]
            def events(s):return [e for b in s["batches"] for e in json.loads(base64.b64decode(b["bytes"]))]
            def binding(s):return s["binding"]["lane"]["allowed"]["_0"]
            def key(t):return (t["kind"],t["index"],t["inputDigest"])
            def close(x,y):return len(x)==len(y) and all(math.isfinite(v) and math.isfinite(w) and abs(v-w)<=1e-6+1e-5*abs(v) for v,w in zip(x,y))
            def success(s,n=None):
                e=events(s);a=binding(s)
                assert set(e[-2])=={"usage"} and e[-1]=={"finished":{"_0":{"complete":{}}}}
                assert sum("usage" in x for x in e)==1 and sum("finished" in x for x in e)==1
                calls=[x["toolCallAppendArguments"] for x in e if "toolCallAppendArguments" in x]
                if n is None:assert not calls
                else:
                    assert [c["name"] for c in calls]==["alpha","beta"]
                    assert [json.loads(c["content"]) for c in calls]==[{"n":n},{"message":"Retain ordered values. "*8}]
                    for i,c in enumerate(calls):
                        digest=hashlib.sha256(("S75-ID-v1:"+a["namespace"]+":"+str(i)).encode()).hexdigest()
                        assert c["entryID"]==a["entryID"] and c["id"]=="call_"+digest[:32]
                    assert e[-2]["usage"]["outputTokens"]>a["probeOptions"]["maximumTokens"]
                assert e[-2]["usage"]["inputTokens"]==sum(len(t["preparedTokens"]) for t in s["traces"])
            # Check bounded variant feasibility before the longer continuation pairs.
            for variant in ("eight","zero","short"):
                path=run("reference",self.fixtures/("state-"+variant),"state-"+variant,"state",variant)
                shutil.copy2(path,self.evidence/path.name);s=json.loads(path.read_text());self.mlx_peak=max(self.mlx_peak,s["peak"]);e=events(s)
                if variant=="eight":success(s,8)
                elif variant=="zero":success(s);assert s["calls"]==0 and len(e)==2 and e[-2]["usage"]["outputTokens"]==0
                else:
                    assert "error" in e[-1]["finished"]["_0"] and not any("usage" in x for x in e)
                    calls=[x["toolCallAppendArguments"] for x in e if "toolCallAppendArguments" in x]
                    assert len(calls)==1 and calls[0]["name"]=="alpha" and json.loads(calls[0]["content"])=={"n":7}
                self.record("state-"+variant,result="PASS",snapshot_sha256=sha(path),calls=s["calls"],events=e)
            for family in ("llama","state"):
                reference=run("reference",self.fixtures/(family+"-reference"),family+"-reference",family,"llama" if family=="llama" else "calls")
                cuts=("probe",) if family=="llama" else ("probe","guided")
                for cut in cuts:
                    label=family+"-"+cut;active=self.fixtures/(label+"-active")
                    checkpoint=run("checkpoint-"+cut,active,label+"-checkpoint",family,"llama" if family=="llama" else "calls")
                    recovered=run("recover",active,label+"-recovered",family)
                    # Fresh argv contains fixed fixture family plus mode/root/output.
                    # Read comparison oracles only after positive restored work and join.
                    a,b,c=[json.loads(p.read_text()) for p in (reference,checkpoint,recovered)]
                    for path in (reference,checkpoint,recovered):shutil.copy2(path,self.evidence/path.name)
                    assert a["terminal"] and c["terminal"] and not b["terminal"] and b["calls"]>0 and c["calls"]>0
                    assert a["binding"]==b["binding"]==c["binding"] and a["descriptor"]==b["descriptor"]==c["descriptor"]
                    for k in ("context","contextDigest","reference"):assert b["accepted"][k]==c["accepted"][k]
                    assert a["accepted"]["requestID"]==b["accepted"]["requestID"]=="begin-1" and c["accepted"]["requestID"]=="recover-1"
                    assert batches(a)==batches(b)+batches(c)
                    assert all(c[k]==0 for k in ("requestPreparations","templateCalls","requestTokenizations","entryRequestTokenizations","modelPrepares","issues","begins")) and c["recoveries"]==1
                    assert key(c["traces"][0])==key(b["traces"][-1]) and c["traces"][0]["calls"]>0 and c["traces"][0]["offsets"][0]>0
                    assert c["traces"][0]["kind"]==("probe" if cut=="probe" else "tool")
                    ref={key(t):t for t in a["traces"]};prefix={key(t):t for t in b["traces"]};suffix={key(t):t for t in c["traces"]}
                    assert set(ref)==set(prefix)|set(suffix)
                    for k,t in ref.items():
                        left=prefix.get(k);right=suffix.get(k)
                        for f in ("inputs","offsets"):
                            observed=(left[f] if left else [])+(right[f] if right else []);assert t[f]==observed
                        for f in ("logits","running"):
                            observed=(left[f] if left else [])+(right[f] if right else []);assert len(t[f])==len(observed) and all(close(x,y) for x,y in zip(t[f],observed))
                        for part in (left,right):
                            if part:assert t["preparedTokens"]==part["preparedTokens"] and t["weights"]==part["weights"]
                        assert [x for chunk in t["inputs"] for x in chunk][:len(t["preparedTokens"])]==t["preparedTokens"]
                    assert a["traces"][0]["preparedTokens"]==binding(a)["originalTokens"]
                    # Later passes are new work: each has its own permitted prefill.
                    for t in c["traces"][1:]:assert t["offsets"][0]==0
                    success(a,None if family=="llama" else 7)
                    self.mlx_peak=max(self.mlx_peak,*[s["peak"] for s in (a,b,c)])
                    save(self.evidence/(label+"-native.json"),dict(result="PASS",family=family,cut=cut,reference_calls=a["calls"],checkpoint_calls=b["calls"],fresh_calls=c["calls"],restored_child_calls=c["traces"][0]["calls"],later_passes=len(c["traces"])-1,
                        fresh_counters={k:c[k] for k in ("requestPreparations","templateCalls","requestTokenizations","entryRequestTokenizations","entryRepairEncodes","entryNativeEncodes","repairEncodes","nativeEncodes","factories","modelPrepares","issues","begins","recoveries")},snapshot_sha256={p.name:sha(p) for p in (reference,checkpoint,recovered)},exact_binding_batches_events=True,exact_per_pass_input_offset_suffix=True,logits_rtol=1e-5,logits_atol=1e-6))
                    self.record(label+"-native-recovery",result="PASS")
        def verify(self):
            for p,h in self.inputs.items():assert sha(self.repo/p)==h,p
            for p,h in self.copied.items():assert sha(self.package/p)==h,p
            for p,h in self.outputs.items():assert sha(self.package/"mlx-swift-lm"/p)==h,p
        def finish(self,result):
            # Only these owned S91 fixture trees and the exact old-guard unit root.
            # No Keychain controller exists and no Keychain cleanup API is called.
            super().finish(result)
            shutil.rmtree(self.regression);shutil.rmtree(self.guard_root)
            result.update(regression_root_removed=not self.regression.exists(),guard_root_removed=not self.guard_root.exists(),keychain_calls=0,fixture_keys="known non-secret constants; owned disk content removed")
            save(self.evidence/"results.json",result)
    return Campaign()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--repo",type=Path,required=True)
    args=parser.parse_args();c=make_campaign(args.repo.resolve());print(c.root,flush=True);result=dict(result="FAIL")
    try:
        c.prepare();tests=c.tests();c.workers();c.verify();result=dict(result="PASS",tests=tests,binaries=c.binaries,worker_cases=len(c.matrix))
    finally:c.finish(result)
    print(json.dumps(dict(result=result["result"],evidence=str(c.evidence))),flush=True)
if __name__=="__main__":main()
