#!/usr/bin/env python3
"""Offline CPU-only check of the S75 parser candidate; retain evidence and clean owned copies."""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path
sys.dont_write_bytecode = True
PIN = "83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8"
SELECTED = {'Libraries/MLXLMCommon/Tool/Parsers/GLM4ToolCallParser.swift': '5f64045b596508b321ad235b01bfd2d9aa82807d29e86f1c6f62809ca81f512a', 'Libraries/MLXLMCommon/Tool/Parsers/GemmaFunctionParser.swift': 'dac1976d7c78eaa6d5d9819a0102c6a611917294d97334a3ed8f7750a356cdef', 'Libraries/MLXLMCommon/Tool/Parsers/JSONToolCallParser.swift': '82e8cf2160e564a69075e9b12fbf46489234a830e24b8e654ef8cb9763df25fd', 'Libraries/MLXLMCommon/Tool/Parsers/KimiK2ToolCallParser.swift': 'fd03e6a0a487706587185fdc8947e5d07c907145b5924e1121074584ed597802', 'Libraries/MLXLMCommon/Tool/Parsers/Llama3ToolCallParser.swift': '027b1d58882f18ff4a6259ac81da704873f61e0f5e54dba863bd08c48c39b940', 'Libraries/MLXLMCommon/Tool/Parsers/MiniMaxM2ToolCallParser.swift': 'e8e7d92ac5f6cd045fff79d6ea2cfafcae2a888ee02929ea71ef6b24e74af4e9', 'Libraries/MLXLMCommon/Tool/Parsers/MistralToolCallParser.swift': 'c69b4f46dacbd8981ac04441694299cc6e4619571942afdd8666d77868c0823c', 'Libraries/MLXLMCommon/Tool/Parsers/ParserUtilities.swift': '6b3a947c65709f6dd05fc1f3121517d5c8133e50cc73dd227df8d22ab0f550c7', 'Libraries/MLXLMCommon/Tool/Parsers/PythonicToolCallParser.swift': '9bff3120176308368f6bae64fd701ed02b6abde23a0914845a330e14e0276536', 'Libraries/MLXLMCommon/Tool/Parsers/XMLFunctionParser.swift': '5b5b0e03d4e23c4fb85356008bc9997af5efcbbf8c4d005b189e354642eab7dc', 'Libraries/MLXLMCommon/Tool/Tool.swift': '461d774bc3b60e090dc758bb651ca70779330c397a0aa115cde131b729547209', 'Libraries/MLXLMCommon/Tool/ToolCall.swift': '8b81f253787545ca8abc5d47c4df6bb05ebe286039ee23b23ddb9ad88fe52124', 'Libraries/MLXLMCommon/Tool/ToolCallFormat.swift': 'd1c03dbdf26eb1603efdc080d9dbdb6883bcbd3ba22c09e32d1f9651f97173e5', 'Libraries/MLXLMCommon/Tool/ToolCallProcessor.swift': '8b90b197756abb6529cbb28bb92ed331d50b75d772964bf92527953b8280b35c', 'Libraries/MLXLMCommon/Tool/ToolParameter.swift': '11485173719a25b271b655071b5668c52872ef0447eab963dfe31befb9992846', 'Libraries/MLXLMCommon/Tool/Value.swift': 'b79bf915e3d105e4b36922968924986a251d8edaedef043357c1eb2ca13ee9fc', 'Libraries/MLXLMCommon/ChatConventions.swift': '9573431c68d02ae8a5392666f5a70f0de789a5462ffe4531c2cad7c4f04803ef', 'Libraries/MLXLMCommon/ReasoningConfig.swift': 'c37f7687220aa290294e81f3e310a6aedb94b025b99a095207dfccacd92ca79a', 'Tests/MLXLMTests/ToolTests.swift': 'c94eca51d0c99af37098b7ae8b7ce33ad8763e4b7028fb934bfc01d12255c5ce'}
PREREQUISITES = {'MLXResumableTokenDriver': {'run.py': 'fc3845b52716faf3b981ec6000b92c0af6f56a81be6b56b60f29cf74f03aadff', 'README.md': '75797167434fb5cbc7d8926f4e025e986f715daa796e2443c63591c3078e05d4', 'Package.swift': '4d907ac7995b5fe958f6bf0971fdfcdeedc7abe01953da8b67b69ca8137abee1', 'mlx-swift-lm.patch': '35a3be79e989c39ae568f97a70baf8bdb5b75f3161919803cc8a1530a0db63ab', 'Sources/CheckpointWorker/main.swift': '8ba70b7a70471e3f82ac72d641d1192950356a12d5cedc9c82104f46e4fa6c32'}, 'MLXResumableTextOutput': {'run.py': 'd7a365afdc5f3b5b83e5ac7e0ad419d608f55e2e69f6cb3f9e0771f5ff4b34b7', 'README.md': '54c5ae748a5209ad4d01ac53d6c0ab2c45e410724eedb32c36174090b83c7d1d', 'Package.swift': 'f13bbe3d644b90d359abd7def34102167e63035c093f2d3222be9e265b5b3d63', 'mlx-swift-lm.patch': 'bd3fb02e7fab42887593512599de64ecb4d7c7c242d91359d37158d2a8227113', 'Sources/TextOutputWorker/main.swift': 'e816055c544bf83f313bb63bb2adfc4135b69d92f7a180d3eea2929246fdf7d3'}, 'MLXResumableGuidedGeneration': {'run.py': 'e8c7c66940901bed9188d2b4e65038fb6bdada0514d2fa5cc55a7bc7fcfa287c', 'README.md': 'fac2f59780c043456bac74ff1b1783d00ba4cd8348a03476078896da4d9a67c2', 'Package.swift': '57bacbcd8ffd471b26efeddb97cc8040096657be77cd35f58f2cc58902c2e51a', 'mlx-swift-lm.patch': '91a056cc2094496c1f62a082d718abdd3f2f15de601c0954c79c886af076aa4b', 'Sources/GuidedCheckpointWorker/main.swift': 'fbb61f11007e3fa7f552bc4e7ce26f44bdf774b74c5ee255b4fc10375ce044fa'}}
PRIOR_OUTPUTS = {'Libraries/MLXLMCommon/Evaluate.swift': 'af561a3707edaf84afb2235085a0a581a05feb502ae915c30217060334fa16b3', 'Libraries/MLXLMCommon/LanguageModel.swift': '95edafd10e744b909c2c1f3b7355ff684612d83c49fa9f4515138ac2f7c2c572', 'Libraries/MLXLMCommon/ResumableTokenDriver.swift': '63ebcbaf0123d2da6a8221ead9f7918686a140501e215aaafa73f9adda2e0909', 'Libraries/MLXLMCommon/ResumableTokenCheckpoint.swift': 'e0eefce17c271d43bcf95ba2083079c3d6c83a6361a7fc8d97b0351fca194b75', 'Tests/MLXLMTests/ResumableTokenDriverTests.swift': '02218c0a143f5552eb018a79bc0497ac510805972ce63a5f4ab29fb80ebf8b67', 'Tests/MLXLMTests/ResumableTokenCheckpointTests.swift': 'd7c3208ff12c79e510fef407cd3f67908b9eae3539c8c4947d942b31e62fdc72', 'Libraries/MLXLMCommon/ResumableTextOutput.swift': '6a09466699e95edc57318ff21049e2df8f7cf653d8f1524c6721211908d5e76a', 'Libraries/MLXLMCommon/ResumableTextCheckpoint.swift': 'd29f98e28f418891ad6dbc7b52e9ac1fa1d17ab0b1c54188cfcf61ee3bc3aad1', 'Tests/MLXLMTests/ResumableTextOutputTests.swift': '71273018e4bd2b23d26164a4c1e6bd2eb0fa4cd38efa1a5d814ae4a59d6f902d', 'Tests/MLXLMTests/ResumableTextCheckpointTests.swift': '3c52d5129701ad70381a2ad0192d8506597c3677b5fe186cbaf007ff03c27933', 'Libraries/MLXLMCommon/ResumableGuidedModelState.swift': 'c6df59921c588a870d76eedffebf512e4504e614369e0195d649b5a6dea5d640', 'Libraries/MLXGuidedGeneration/ResumableGuidedGeneration.swift': 'df708ca383a3b79ace8a85effda8fe8723c7f83b6709a71310b69ea558fb2a0e', 'Libraries/MLXGuidedGeneration/ResumableGuidedCheckpoint.swift': '55a8383083b80e4951e2ae96a55f7daf56160696bc653c7d9e0399c76c9fecfa', 'Libraries/MLXGuidedGeneration/ResumableGrammarState.swift': 'd4a14ebe0237a91da2b97702d41309138531faab5de4e7502903cfdd0ab1ffaa', 'Libraries/MLXGuidedGeneration/ResumableGuidedTextState.swift': '71360e0b2b0ac73882c83b46d4532eee2ee1cf1529c30d8ef76a2a6bb396d2ef', 'Libraries/MLXGuidedGeneration/XGrammarBridge.swift': '3c76fa4d976324cde0574f373d7947fcbbebe50f05537c9fc28c752784a04aae', 'Libraries/MLXGuidedGeneration/WhitespaceRunTracker.swift': '4326e12dd2500574256f467f56741776928e81432facc6c3a22d5e6e555318ad', 'Tests/MLXLMTests/ResumableGuidedModelStateTests.swift': '44bb4787f469577dba7f628a865afcf50ef0af07ff21a0cff4d9ff5646c13da2', 'Tests/MLXGuidedGenerationTests/ResumableGuidedGenerationTests.swift': '6d58cbd8bbabc94dd9c7a303d9e540fd2fa0fe706f785f9e9612c0ca13179960', 'Tests/MLXGuidedGenerationTests/ResumableGuidedCheckpointTests.swift': '907ff4fea1a52f1c33c1d0136aac37116cc059475671da4c0616d26ad710dc3e', 'Tests/MLXGuidedGenerationTests/ResumableGrammarStateTests.swift': '35813e02415a90396ac5d719c6bfd3f3928e7b0dc8bc1d7a07f361f3112b9b9e', 'Tests/MLXGuidedGenerationTests/ResumableGuidedTextStateTests.swift': '5f8ee1b8615c8387d9864745109dbc8a4974037bdbbffd3c667b732b9df04123'}
PATCH_PATHS = ['Libraries/MLXLMCommon/Tool/ToolCallProcessor.swift', 'Libraries/MLXLMCommon/Tool/ResumableToolCallProcessor.swift', 'Libraries/MLXLMCommon/Tool/ResumableToolCallCheckpoint.swift', 'Tests/MLXLMTests/ResumableToolCallProcessorTests.swift', 'Tests/MLXLMTests/ResumableToolCallCheckpointTests.swift', 'Libraries/MLXLMCommon/Tool/ToolCallFormat.swift']
CASES = ['c0','tagged','bare','xml-schema','inline','mistral-eos','lfm2-eos','ids','finished']

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path, value): path.write_text(json.dumps(value, indent=2)+'\n')
def git(source, *args): return subprocess.check_output(['git',*args], cwd=source, timeout=30)
def shared_inputs(reach):
    source=reach/'reachd/.build/checkouts/mlx-swift-lm'
    if git(source,'rev-parse','HEAD').decode().strip()!=PIN or git(source,'status','--porcelain','--untracked-files=no').strip():
        raise RuntimeError('pinned parser source revision/cleanliness mismatch')
    for directory, hashes in PREREQUISITES.items():
        if {name:sha(reach/'Tools'/directory/name) for name in hashes}!=hashes:
            raise RuntimeError('accepted prerequisite products changed: '+directory)
    return source

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reach',type=Path,required=True)
    args=parser.parse_args(); reach=args.reach.resolve(); candidate=Path(__file__).resolve().parent
    os.umask(0o077)
    root=Path(tempfile.mkdtemp(prefix='reach-mlx-tool-call.',dir='/private/tmp'))
    private=root/'private'; logs=root/'logs'; evidence=root/'evidence'
    for directory in (private,logs,evidence,private/'tmp',private/'fixtures'):directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    print('Evidence: '+str(root),flush=True)
    commands=[]; observations=[]; started=time.monotonic()
    outcome={'result':'FAIL','proof':'local CPU-only parser checkpoint candidate, same namespace and chunk sequence',
             'reused':'S72/S73/S74 accepted native campaigns; source composition only, no generation/parser route or model rerun'}
    env=dict(os.environ); env.update(CLANG_MODULE_CACHE_PATH=str(private/'clang-cache'),SWIFTPM_MODULECACHE_OVERRIDE=str(private/'swift-cache'),XDG_CACHE_HOME=str(private/'xdg'),TMPDIR=str(private/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    def interrupted(_signal,_frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,interrupted)
    def resources(label):
        allocated=int(subprocess.check_output(['du','-sk',str(root)],text=True).split()[0])*1024
        fixture_bytes=sum(p.stat().st_size for directory in (private/'fixtures',private/'tmp') for p in directory.rglob('*') if p.is_file())
        free=shutil.disk_usage(root).free
        observations.append({'after':label,'allocated_bytes':allocated,'fixture_bytes':fixture_bytes,'free_bytes':free})
        if allocated>4*1024**3 or fixture_bytes>16*1024**2 or free<2*1024**3:raise RuntimeError('S75 resource ceiling/floor')
    def command(label,cmd,cwd,timeout=300):
        before=time.monotonic()
        with (logs/(label+'.log')).open('w') as log:
            process=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=process.wait(timeout=timeout)
            except BaseException:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
                raise
        commands.append({'label':label,'command':cmd,'exit_code':code,'seconds':time.monotonic()-before,'joined':True})
        dump(evidence/'commands.json',commands); resources(label)
        if code:raise RuntimeError(f'{label} failed with exit {code}; see {logs/(label+".log")}')
        return (logs/(label+'.log')).read_text()
    try:
        resources('opening'); source=shared_inputs(reach)
        inputs={'reach_head':git(reach,'rev-parse','HEAD').decode().strip(),'pin':PIN,'selected_source_sha256':SELECTED,
                'prerequisite_products':PREREQUISITES,'candidate_sha256':{str(p.relative_to(candidate)):sha(p) for p in candidate.rglob('*') if p.is_file()},
                'developer':subprocess.check_output(['xcode-select','-p'],text=True).strip(),
                'swift':subprocess.check_output(['xcrun','swift','--version'],text=True,stderr=subprocess.STDOUT).strip(),'python':sys.version}
        dump(evidence/'inputs.json',inputs)
        harness=private/'harness'; lm=harness/'lm'; lm.mkdir(parents=True)
        for name,digest in SELECTED.items():
            data=git(source,'show',PIN+':'+name)
            if hashlib.sha256(data).hexdigest()!=digest or sha(source/name)!=digest:raise RuntimeError('selected source bytes mismatch: '+name)
            target=lm/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
        patch=candidate/'mlx-swift-lm.patch'
        paths=re.findall(r'^diff --git a/(\S+) b/(\S+)$',patch.read_text(),re.M)
        if not paths or len(paths)>6 or len(set(a for a,b in paths))!=len(paths) or any(a!=b or a not in PATCH_PATHS for a,b in paths):raise RuntimeError('S75 patch path ceiling')
        command('candidate-patch-check',['git','apply','--check',str(patch)],lm,30)
        command('candidate-patch-apply',['git','apply',str(patch)],lm,30)
        outputs={a:sha(lm/a) for a,b in paths}
        for name,digest in SELECTED.items():
            if name not in outputs and sha(lm/name)!=digest:raise RuntimeError('unchanged selected parser/test changed')
        dump(evidence/'patched-source-sha256.json',outputs)
        # Source-only composition. Export just the tracked base files needed by
        # the four patches, never prior model build/runtime or protected paths.
        composition=private/'composition'; composition.mkdir()
        tracked=set(git(source,'ls-tree','-r','--name-only',PIN).decode().splitlines())
        for name in set(PRIOR_OUTPUTS)|set(outputs):
            if name in tracked:
                target=composition/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(git(source,'show',PIN+':'+name))
        stack=[]
        for directory in PREREQUISITES:
            prior_patch=reach/'Tools'/directory/'mlx-swift-lm.patch'
            command(directory+'-compose',['git','apply',str(prior_patch)],composition,30)
            stack.append({'tool':directory,'patch_sha256':sha(prior_patch)})
        if {name:sha(composition/name) for name in PRIOR_OUTPUTS}!=PRIOR_OUTPUTS:raise RuntimeError('prior output binding mismatch')
        command('s75-compose-check',['git','apply','--check',str(patch)],composition,30)
        command('s75-compose',['git','apply',str(patch)],composition,30)
        if {name:sha(composition/name) for name in PRIOR_OUTPUTS}!=PRIOR_OUTPUTS or {name:sha(composition/name) for name in outputs}!=outputs:raise RuntimeError('source composition changed outputs')
        dump(evidence/'composition.json',{'result':'PASS','ordered_prerequisites':stack,'s75_patch_sha256':sha(patch),'unchanged_22_prior_outputs':PRIOR_OUTPUTS,'s75_outputs':outputs,'claim':'source-only; no joined runtime or native model rerun'})
        shutil.copy2(candidate/'Package.swift',harness/'Package.swift')
        worker=harness/'Sources/ToolCallCheckpointWorker/main.swift'; worker.parent.mkdir(parents=True); shutil.copy2(candidate/'Sources/ToolCallCheckpointWorker/main.swift',worker)
        flags=['--package-path',str(harness),'--scratch-path',str(private/'build'),'--cache-path',str(private/'cache'),'--config-path',str(private/'config'),'--security-path',str(private/'security'),'--disable-sandbox','--disable-netrc','--disable-keychain','--disable-dependency-cache','--disable-prefetching','--skip-update','--disable-index-store','--jobs','4']
        command('candidate-build',['xcrun','swift','build',*flags,'--build-tests'],harness)
        binary_path=subprocess.check_output(['xcrun','swift','build',*flags,'--show-bin-path'],cwd=harness,env=env,text=True,stderr=subprocess.PIPE).strip()
        binary=Path(binary_path)/'ToolCallCheckpointWorker'
        test_log=command('candidate-tests',['xcrun','swift','test',*flags,'--skip-build','--no-parallel','--filter','ToolTests|ResumableToolCall'],harness)
        executed=re.findall(r"Test Case '-\[MLXLMTests\.(\w+) (test\w+)\]' passed",test_log)
        if len(executed)!=9 or len(set(executed))!=9 or 'Executed 9 tests, with 0 failures' not in test_log or 'Test run with 63 tests in 1 suite passed' not in test_log:raise RuntimeError('actual test selection/count mismatch')
        # Record each legacy title too; declaration counts are not execution proof.
        legacy=re.findall(r'Test "(.*)" passed after',test_log)
        if len(legacy)!=63 or len(set(legacy))!=63:raise RuntimeError('legacy executed titles mismatch')
        dump(evidence/'tests.json',{'new_methods':['.'.join(x) for x in executed],'legacy_titles':legacy})
        print('9 new XCTest methods and 63 unchanged compatibility tests PASS',flush=True)
        matrix=[]
        for name in CASES:
            fixture=private/'fixtures'/name
            args=[name,str(fixture.with_suffix('.checkpoint')),str(fixture.with_suffix('.continuation')),str(fixture.with_suffix('.expected'))]
            pair=[]
            for mode in ('produce','restore'):
                row=json.loads(command(name+'-'+mode,[str(binary),mode,*args],harness,30))
                if row['result']!='PASS' or row['checkpoint_bytes']>1024*1024:raise RuntimeError('worker refusal/bound')
                pair.append(row)
            if pair[0]['pid']==pair[1]['pid'] or {k:v for k,v in pair[0].items() if k not in ('pid','mode')}!={k:v for k,v in pair[1].items() if k not in ('pid','mode')}:raise RuntimeError('fresh process binding/suffix mismatch')
            matrix+=pair; dump(evidence/'matrix.json',matrix)
        shared_inputs(reach)
        outcome.update(result='PASS',new_xctest_methods=9,legacy_tests=63,fresh_process_pairs=9,sequential_workers=18,
                       maximum_checkpoint_bytes=max(x['checkpoint_bytes'] for x in matrix),worker_binary_sha256=sha(binary))
        print('9 sequential fresh-process continuation pairs PASS',flush=True)
    except Exception as error:
        outcome['error']=str(error); print(str(error),file=sys.stderr)
    finally:
        outcome['seconds']=time.monotonic()-started
        dump(evidence/'resources.json',{'observations':observations,'note':'Command-boundary observations, not continuous resource peaks.'})
        shutil.rmtree(private)
        outcome['owned_private_removed']=not private.exists()
        outcome['supervision']='One build/test or fixture worker at a time; at most four build jobs. Each owned command joined; timeout signals its owned process group and joins. No exhaustive opaque descendant claim.'
        dump(evidence/'results.json',outcome); print(json.dumps(outcome,indent=2))
    return 0 if outcome['result']=='PASS' else 1

if __name__=='__main__':sys.exit(main())
