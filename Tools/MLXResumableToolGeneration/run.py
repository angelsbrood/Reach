#!/usr/bin/env python3
"""Offline native check of the local tool-generation dependency candidate; retain logs, clean owned copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
PINS = {
    "mlx-swift-lm": "83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8",
    "mlx-swift": "0bb916c67f4b9e5c682cbe02a42c701c93ab5021",
    "swift-numerics": "0c0290ff6b24942dadb83a929ffaaa1481df04a2",
    "swift-argument-parser": "6a52f3251125d74daf04fcbd5e6f08a75d074382",
}
METALLIB = "reachd/.build/out/Products/Debug/mlx-swift_Cmlx.bundle/Contents/Resources/default.metallib"
METALLIB_SHA = "684ec284ab6f1f0a4089acfc3f91c1bde801747626c28f69defb65c1193db8a5"
PREREQUISITES = {'MLXResumableTokenDriver': {'run.py': 'fc3845b52716faf3b981ec6000b92c0af6f56a81be6b56b60f29cf74f03aadff',
                             'README.md': '75797167434fb5cbc7d8926f4e025e986f715daa796e2443c63591c3078e05d4',
                             'Package.swift': '4d907ac7995b5fe958f6bf0971fdfcdeedc7abe01953da8b67b69ca8137abee1',
                             'mlx-swift-lm.patch': '35a3be79e989c39ae568f97a70baf8bdb5b75f3161919803cc8a1530a0db63ab',
                             'Sources/CheckpointWorker/main.swift': '8ba70b7a70471e3f82ac72d641d1192950356a12d5cedc9c82104f46e4fa6c32'},
 'MLXResumableTextOutput': {'run.py': 'd7a365afdc5f3b5b83e5ac7e0ad419d608f55e2e69f6cb3f9e0771f5ff4b34b7',
                            'README.md': '54c5ae748a5209ad4d01ac53d6c0ab2c45e410724eedb32c36174090b83c7d1d',
                            'Package.swift': 'f13bbe3d644b90d359abd7def34102167e63035c093f2d3222be9e265b5b3d63',
                            'mlx-swift-lm.patch': 'bd3fb02e7fab42887593512599de64ecb4d7c7c242d91359d37158d2a8227113',
                            'Sources/TextOutputWorker/main.swift': 'e816055c544bf83f313bb63bb2adfc4135b69d92f7a180d3eea2929246fdf7d3'},
 'MLXResumableGuidedGeneration': {'run.py': 'e8c7c66940901bed9188d2b4e65038fb6bdada0514d2fa5cc55a7bc7fcfa287c',
                                  'README.md': 'fac2f59780c043456bac74ff1b1783d00ba4cd8348a03476078896da4d9a67c2',
                                  'Package.swift': '57bacbcd8ffd471b26efeddb97cc8040096657be77cd35f58f2cc58902c2e51a',
                                  'mlx-swift-lm.patch': '91a056cc2094496c1f62a082d718abdd3f2f15de601c0954c79c886af076aa4b',
                                  'Sources/GuidedCheckpointWorker/main.swift': 'fbb61f11007e3fa7f552bc4e7ce26f44bdf774b74c5ee255b4fc10375ce044fa'},
 'MLXResumableToolCallParsing': {'run.py': '94af8c47103c5194a3373a8706f3f5ba7135ae75723f3ffe8b394fa07fe0adbe',
                                 'README.md': '786cfb47a6ac16d89d85e45a634610563928113d8030740162f41b1cb20b1a10',
                                 'Package.swift': '838b5b14c13f342609c8325da103a0db9bee8a7213b82484a6bdd11903575bf4',
                                 'mlx-swift-lm.patch': 'c7ae60342894f77b58e3b5cb51a11b0a1251db95a7bbc9386307eb17cec27ffd',
                                 'Sources/ToolCallCheckpointWorker/main.swift': 'a29281ac94988a2f32f5b1fab43470e1917f27a553548c04e0548aa1c583c6b3'}}
PRIOR_OUTPUTS = {'Libraries/MLXGuidedGeneration/ResumableGrammarState.swift': 'd4a14ebe0237a91da2b97702d41309138531faab5de4e7502903cfdd0ab1ffaa',
 'Libraries/MLXGuidedGeneration/ResumableGuidedCheckpoint.swift': '55a8383083b80e4951e2ae96a55f7daf56160696bc653c7d9e0399c76c9fecfa',
 'Libraries/MLXGuidedGeneration/ResumableGuidedGeneration.swift': 'df708ca383a3b79ace8a85effda8fe8723c7f83b6709a71310b69ea558fb2a0e',
 'Libraries/MLXGuidedGeneration/ResumableGuidedTextState.swift': '71360e0b2b0ac73882c83b46d4532eee2ee1cf1529c30d8ef76a2a6bb396d2ef',
 'Libraries/MLXGuidedGeneration/WhitespaceRunTracker.swift': '4326e12dd2500574256f467f56741776928e81432facc6c3a22d5e6e555318ad',
 'Libraries/MLXGuidedGeneration/XGrammarBridge.swift': '3c76fa4d976324cde0574f373d7947fcbbebe50f05537c9fc28c752784a04aae',
 'Libraries/MLXLMCommon/Evaluate.swift': 'af561a3707edaf84afb2235085a0a581a05feb502ae915c30217060334fa16b3',
 'Libraries/MLXLMCommon/LanguageModel.swift': '95edafd10e744b909c2c1f3b7355ff684612d83c49fa9f4515138ac2f7c2c572',
 'Libraries/MLXLMCommon/ResumableGuidedModelState.swift': 'c6df59921c588a870d76eedffebf512e4504e614369e0195d649b5a6dea5d640',
 'Libraries/MLXLMCommon/ResumableTextCheckpoint.swift': 'd29f98e28f418891ad6dbc7b52e9ac1fa1d17ab0b1c54188cfcf61ee3bc3aad1',
 'Libraries/MLXLMCommon/ResumableTextOutput.swift': '6a09466699e95edc57318ff21049e2df8f7cf653d8f1524c6721211908d5e76a',
 'Libraries/MLXLMCommon/ResumableTokenCheckpoint.swift': 'e0eefce17c271d43bcf95ba2083079c3d6c83a6361a7fc8d97b0351fca194b75',
 'Libraries/MLXLMCommon/ResumableTokenDriver.swift': '63ebcbaf0123d2da6a8221ead9f7918686a140501e215aaafa73f9adda2e0909',
 'Libraries/MLXLMCommon/Tool/ResumableToolCallCheckpoint.swift': '8c2ac93dd8639290c74ce760f10424c0b8213908c0f409c915461a9a90cb3e86',
 'Libraries/MLXLMCommon/Tool/ResumableToolCallProcessor.swift': '6f516e23174eab3cc55a1deac9b10de3e4e858ac5a86706f25a1891b05438b8f',
 'Libraries/MLXLMCommon/Tool/ToolCallProcessor.swift': '18d392604bf09e5119e56c9378c0d2df8e8a22b01ef8969dace19c15c5ed5515',
 'Tests/MLXGuidedGenerationTests/ResumableGrammarStateTests.swift': '35813e02415a90396ac5d719c6bfd3f3928e7b0dc8bc1d7a07f361f3112b9b9e',
 'Tests/MLXGuidedGenerationTests/ResumableGuidedCheckpointTests.swift': '907ff4fea1a52f1c33c1d0136aac37116cc059475671da4c0616d26ad710dc3e',
 'Tests/MLXGuidedGenerationTests/ResumableGuidedGenerationTests.swift': '6d58cbd8bbabc94dd9c7a303d9e540fd2fa0fe706f785f9e9612c0ca13179960',
 'Tests/MLXGuidedGenerationTests/ResumableGuidedTextStateTests.swift': '5f8ee1b8615c8387d9864745109dbc8a4974037bdbbffd3c667b732b9df04123',
 'Tests/MLXLMTests/ResumableGuidedModelStateTests.swift': '44bb4787f469577dba7f628a865afcf50ef0af07ff21a0cff4d9ff5646c13da2',
 'Tests/MLXLMTests/ResumableTextCheckpointTests.swift': '3c52d5129701ad70381a2ad0192d8506597c3677b5fe186cbaf007ff03c27933',
 'Tests/MLXLMTests/ResumableTextOutputTests.swift': '71273018e4bd2b23d26164a4c1e6bd2eb0fa4cd38efa1a5d814ae4a59d6f902d',
 'Tests/MLXLMTests/ResumableTokenCheckpointTests.swift': 'd7c3208ff12c79e510fef407cd3f67908b9eae3539c8c4947d942b31e62fdc72',
 'Tests/MLXLMTests/ResumableTokenDriverTests.swift': '02218c0a143f5552eb018a79bc0497ac510805972ce63a5f4ab29fb80ebf8b67',
 'Tests/MLXLMTests/ResumableToolCallCheckpointTests.swift': '6a5c1158c1523b64b7dfe8310ac9e74b8d1babe0ef34f6dc138a26378a1e2862',
 'Tests/MLXLMTests/ResumableToolCallProcessorTests.swift': '2124e82a03341cb7f1483b1674182944dc16c30527f4c1fa084feda6097c0253'}
PATCH_PATHS = {"Libraries/MLXLMCommon/ResumableToolGeneration.swift",
    "Libraries/MLXLMCommon/ResumableToolGenerationCheckpoint.swift",
    "Tests/MLXLMTests/ResumableToolGenerationTests.swift",
    "Tests/MLXLMTests/ResumableToolGenerationCheckpointTests.swift"}
TEST_SOURCES = ["ResumableToolGenerationTests.swift", "ResumableToolGenerationCheckpointTests.swift"]
SELECTION = "ResumableToolGenerationTests|ResumableToolGenerationCheckpointTests"
CASES = ["c0", "partial-tag", "unicode", "ids", "stop-prefix", "normal-terminal", "schema",
         "specialized-eos", "cancel-boundary", "cancel-terminal", "llama"]
PRODUCT_PATHS = {"run.py", "README.md", "Package.swift", "mlx-swift-lm.patch", "Sources/ToolGenerationWorker/main.swift"}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def export_git(source, target, revision, records):
    """Export tracked bytes and each already-present pinned submodule, without fetching."""
    if git(source, "rev-parse", "HEAD") != revision or git(source, "status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError(f"source revision/cleanliness mismatch: {source}")
    target.mkdir(parents=True, exist_ok=True)
    archive = target.parent / (target.name + ".tar")
    subprocess.run(["git", "archive", "--format=tar", "--output=" + str(archive), revision], cwd=source, check=True)
    with tarfile.open(archive) as data:
        data.extractall(target, filter="data")
    archive.unlink()
    records[str(source)] = revision
    entries = subprocess.check_output(["git", "ls-tree", "-r", "-z", revision], cwd=source).split(b"\0")
    for entry in entries:
        if entry.startswith(b"160000 "):
            header, relative = entry.decode().split("\t", 1)
            export_git(source / relative, target / relative, header.split()[2], records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reach", type=Path, required=True)
    parser.add_argument("--companion-root", type=Path, help="Owned S76 development scratch to include in resource observations")
    args = parser.parse_args()
    reach = args.reach.resolve()
    candidate = Path(__file__).resolve().parent
    companion = args.companion_root
    if companion:
        if companion.is_symlink() or companion.parent != Path('/private/tmp') or not companion.name.startswith('reach-s76.'):
            raise RuntimeError('unexpected companion root')
        info = companion.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
            raise RuntimeError('companion ownership/mode')
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    root = Path(tempfile.mkdtemp(prefix='reach-mlx-tool-generation.', dir='/private/tmp')).resolve()
    private, logs, evidence = (root / p for p in ('private','logs','evidence'))
    for p in (private,logs,evidence): p.mkdir(mode=0o700)
    for n in ('tmp','fixtures'): (private/n).mkdir()
    fixtures = private/'fixtures'
    print(f'Evidence: {root}', flush=True)
    commands, observations, revisions = [], [], {}
    outcome = {'result':'FAIL','proof':'local native unconstrained tool-aware generation/proposal checkpoint candidate',
        'reused':'Accepted S72/S73/S74/S75 native campaigns; no unchanged suite or guided/model campaign rerun'}
    started = time.monotonic()
    env = dict(os.environ)
    for name in ('MLX_SWIFT_BUILD_DOC','SPI_GENERATE_DOCS'): env.pop(name,None)
    env.update(CLANG_MODULE_CACHE_PATH=str(private/'clang-cache'),SWIFTPM_MODULECACHE_OVERRIDE=str(private/'swift-cache'),
        XDG_CACHE_HOME=str(private/'xdg-cache'),TMPDIR=str(private/'tmp'),PYTHONDONTWRITEBYTECODE='1')

    def resources(label):
        roots = [root] + ([companion] if companion else [])
        allocated = sum(int(subprocess.check_output(['du','-sk',str(p)],text=True).split()[0])*1024 for p in roots)
        fixture_bytes = sum(p.stat().st_size for r in roots for role in ('fixtures','tmp')
            for p in (r/'private'/role).rglob('*') if p.is_file())
        free = shutil.disk_usage(root).free
        observations.append({'after':label,'combined_allocated_bytes':allocated,'fixture_bytes':fixture_bytes,'free_bytes':free})
        if allocated > 16*1024**3 or fixture_bytes > 64*1024**2 or free < 20*1024**3:
            raise RuntimeError('S76 resource ceiling/floor')

    def command(label, cmd, cwd, timeout=900):
        t = time.monotonic()
        resources(label+'-before')
        with (logs/(label+'.log')).open('w') as log:
            process = subprocess.Popen(cmd,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except BaseException:
                try: os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError: pass
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL); process.wait()
                commands.append({'label':label,'command':cmd,'exit_code':process.returncode,'interrupted':True})
                write_json(evidence/'commands.json',commands)
                raise
        commands.append({'label':label,'command':cmd,'exit_code':code,'seconds':time.monotonic()-t})
        write_json(evidence/'commands.json',commands)
        resources(label+'-after')
        if code: raise RuntimeError(f'{label} exited {code}; see {logs/(label+".log")}')
        return (logs/(label+'.log')).read_text()

    def authenticate_products():
        for name, files in PREREQUISITES.items():
            if {p:sha(reach/'Tools'/name/p) for p in files} != files:
                raise RuntimeError(f'accepted prerequisite changed: {name}')

    try:
        resources('opening')
        developer = subprocess.check_output(['xcode-select','-p'],text=True).strip()
        swift = subprocess.check_output(['xcrun','swift','--version'],text=True,stderr=subprocess.STDOUT).strip()
        if developer != '/Applications/Xcode-beta.app/Contents/Developer' or 'swiftlang-6.4.0.33.1' not in swift:
            raise RuntimeError('selected toolchain mismatch')
        resolved = {p['identity']:p['state']['revision'] for p in json.loads((reach/'reachd/Package.resolved').read_text())['pins']}
        if any(resolved.get(k) != v for k,v in PINS.items()) or sha(reach/METALLIB) != METALLIB_SHA:
            raise RuntimeError('pin/Metal library mismatch')
        authenticate_products()
        files = {str(p.relative_to(candidate)):sha(p) for p in candidate.rglob('*') if p.is_file()}
        if set(files) != PRODUCT_PATHS: raise RuntimeError('five-product ceiling')
        write_json(evidence/'inputs.json',{'reach_head':git(reach,'rev-parse','HEAD'),'prerequisite_products':PREREQUISITES,
            'candidate_sha256':files,'pins':PINS,'metallib_sha256':METALLIB_SHA,'developer':developer,'swift':swift,'python':sys.version})
        harness = private/'harness'; harness.mkdir()
        for name,revision in PINS.items():
            destination = harness/name if name == 'mlx-swift-lm' else private/name
            export_git(reach/'reachd/.build/checkouts'/name,destination,revision,revisions)
        write_json(evidence/'source-revisions.json',revisions)
        manifest = private/'mlx-swift/Package.swift'; text = manifest.read_text()
        for name in ('swift-numerics','swift-argument-parser'):
            original = f'.package(url: "https://github.com/apple/{name}", from: "1.0.0")'
            if text.count(original) != 1: raise RuntimeError('local manifest overlay mismatch')
            text = text.replace(original,f'.package(path: "../{name}")')
        manifest.write_text(text)
        lm = harness/'mlx-swift-lm'
        stack = []
        for index,name in enumerate(PREREQUISITES,72):
            patch = reach/'Tools'/name/'mlx-swift-lm.patch'
            command(f's{index}-patch-check',['git','apply','--check',str(patch)],lm,30)
            command(f's{index}-patch-apply',['git','apply',str(patch)],lm,30)
            stack.append({'slice':f'S{index}','patch_sha256':sha(patch)})
        if {p:sha(lm/p) for p in PRIOR_OUTPUTS} != PRIOR_OUTPUTS:
            raise RuntimeError('27 prior composition output bindings')
        patch = candidate/'mlx-swift-lm.patch'
        paths = re.findall(r'^diff --git a/(\S+) b/(\S+)$',patch.read_text(),re.M)
        if len(paths) != 4 or {a for a,b in paths} != PATCH_PATHS or any(a != b for a,b in paths):
            raise RuntimeError('four additive dependency paths')
        if any((lm/p).exists() for p in PATCH_PATHS): raise RuntimeError('S76 outputs are not additive')
        command('s76-patch-check',['git','apply','--check',str(patch)],lm,30)
        command('s76-patch-apply',['git','apply',str(patch)],lm,30)
        if {p:sha(lm/p) for p in PRIOR_OUTPUTS} != PRIOR_OUTPUTS: raise RuntimeError('S76 changed prerequisite source')
        outputs = {p:sha(lm/p) for p in sorted(PATCH_PATHS)}
        write_json(evidence/'composition.json',{'result':'PASS','ordered_prerequisites':stack,'unchanged_27_prior_outputs':PRIOR_OUTPUTS,
            's76_patch_sha256':sha(patch),'s76_outputs':outputs,'claim':'source composition; S76 native lane excludes S74 guidance/C++ targets'})
        write_json(evidence/'patched-source-sha256.json',{**PRIOR_OUTPUTS,**outputs})
        for name in ('TinyLlama','FocusedTests','Sources/ToolGenerationWorker'): (harness/name).mkdir(parents=True)
        for path in ('LLMModel.swift','Models/Llama.swift'):
            shutil.copy2(lm/'Libraries/MLXLLM'/path,harness/'TinyLlama'/Path(path).name)
        for name in TEST_SOURCES: shutil.copy2(lm/'Tests/MLXLMTests'/name,harness/'FocusedTests'/name)
        shutil.copy2(candidate/'Package.swift',harness/'Package.swift')
        shutil.copy2(candidate/'Sources/ToolGenerationWorker/main.swift',harness/'Sources/ToolGenerationWorker/main.swift')
        # The same native fixture definitions are compiled in tests and fresh workers.
        test_text = (harness/'FocusedTests'/TEST_SOURCES[0]).read_text()
        worker_text = (harness/'Sources/ToolGenerationWorker/main.swift').read_text()
        if test_text.split('import XCTest\n')[0] != worker_text.split('struct TGWorkerCase')[0]:
            raise RuntimeError('test/worker native fixture definitions differ')
        build = private/'build'
        flags = ['--package-path',str(harness),'--scratch-path',str(build),'--cache-path',str(private/'spm-cache'),
            '--config-path',str(private/'spm-config'),'--security-path',str(private/'spm-security'),'--disable-sandbox',
            '--disable-netrc','--disable-keychain','--disable-dependency-cache','--disable-prefetching','--skip-update',
            '--disable-index-store','--build-system','native','--jobs','4']
        path_output = command('binary-path',['xcrun','swift','build',*flags,'--show-bin-path'],harness,60)
        paths = [line.strip() for line in path_output.splitlines() if line.strip().startswith(str(build)+'/')]
        if len(paths) != 1: raise RuntimeError('native binary path observation')
        bin_path = Path(paths[0])
        bin_path.mkdir(parents=True,exist_ok=True)
        binary = bin_path/'ToolGenerationWorker'
        shutil.copy2(reach/METALLIB,bin_path/'mlx.metallib'); shutil.copy2(reach/METALLIB,harness/'default.metallib')
        command('candidate-build',['xcrun','swift','build',*flags,'--build-tests'],harness)
        for bundle in build.rglob('*.xctest'):
            target = bundle/'Contents/MacOS'; target.mkdir(parents=True,exist_ok=True)
            shutil.copy2(reach/METALLIB,target/'mlx.metallib')
        test_log = command('focused-tests',['xcrun','swift','test',*flags,'--skip-build','--no-parallel','--filter',SELECTION],harness,300)
        selected = sorted(re.findall(r'func (test\w+)\(', ''.join((harness/'FocusedTests'/n).read_text() for n in TEST_SOURCES)))
        passed = sorted(re.findall(r"Test Case '-\[MLXLMTests\.\w+ (test\w+)\]' passed",test_log))
        if len(selected) != 11 or selected != passed or 'Executed 11 tests, with 0 failures' not in test_log:
            raise RuntimeError('focused test enumeration/result mismatch')
        write_json(evidence/'tests.json',{'result':'PASS','selected_methods':selected,'passed_methods':passed,'count':len(passed)})
        print('11 focused native tests PASS',flush=True)
        matrix = []
        for name in CASES:
            checkpoint, expected = fixtures/(name+'.checkpoint'), fixtures/(name+'.expected')
            pair = []
            for mode in ('produce','restore'):
                row = json.loads(command(name+'-'+mode,[str(binary),mode,name,str(checkpoint),str(expected)],harness,60))
                if row['result'] != 'PASS' or checkpoint.stat().st_size > 32*1024**2 or expected.stat().st_size > 48*1024**2:
                    raise RuntimeError('fresh worker result or fixture bounds')
                pair.append(row)
            if pair[0]['pid'] == pair[1]['pid']: raise RuntimeError('producer and restore are not distinct processes')
            for key in ('checkpoint_sha256','suffix_records_sha256','suffix_batches','parser_state','parser_sequence','forwarded_chunks','allocation_position','disposition'):
                if pair[0][key] != pair[1][key]: raise RuntimeError('fresh pair binding: '+key)
            matrix.extend(pair); write_json(evidence/'matrix.json',matrix)
            checkpoint.unlink(); expected.unlink()
        authenticate_products()
        for source,revision in revisions.items():
            if git(source,'rev-parse','HEAD') != revision or git(source,'status','--porcelain','--untracked-files=no'):
                raise RuntimeError('shared dependency source changed')
        if {str(p.relative_to(candidate)):sha(p) for p in candidate.rglob('*') if p.is_file()} != files:
            raise RuntimeError('candidate changed during run')
        outcome.update(result='PASS',new_xctest_methods=len(passed),fresh_process_pairs=len(matrix)//2,sequential_workers=len(matrix),
            worker_binary_sha256=sha(binary),maximum_checkpoint_bytes=max(x['checkpoint_bytes'] for x in matrix),
            maximum_mlx_peak_bytes=max(x['mlx_peak_bytes'] for x in matrix),maximum_weight_bytes=max(x['weight_bytes'] for x in matrix))
        print('11 fresh native producer/restore pairs PASS',flush=True)
    except Exception as error:
        outcome.update(result='FAIL',error=str(error)); print(str(error),file=sys.stderr)
    finally:
        outcome['seconds'] = time.monotonic()-started
        outcome['supervision'] = 'At most four build jobs; one build/test or worker at a time; owned commands joined. Timeout signals the owned process group and joins. No exhaustive opaque descendant claim.'
        write_json(evidence/'resources.json',{'observations':observations,'companion_root':str(companion) if companion else None,
            'note':'Command-boundary observations, not continuous resource peaks.'})
        shutil.rmtree(private)
        outcome['owned_source_build_fixture_copies_removed'] = not private.exists()
        write_json(evidence/'results.json',outcome)
        print(json.dumps(outcome,indent=2))
    return 0 if outcome['result'] == 'PASS' else 1

if __name__ == '__main__':
    sys.exit(main())
