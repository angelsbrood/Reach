import Foundation
import Darwin

private let sourcePaths = [
    "Tools/AcceptanceController/Package.swift",
    "Tools/AcceptanceController/Sources/AcceptanceControllerCore/Types.swift",
    "Tools/AcceptanceController/Sources/AcceptanceControllerCore/ResourceLedger.swift",
    "Tools/AcceptanceController/Sources/AcceptanceControllerCore/ProcessRunner.swift",
    "Tools/AcceptanceController/Sources/AcceptanceControllerCore/EvidenceStore.swift",
    "Tools/AcceptanceController/Sources/AcceptanceControllerCore/PacketPublisher.swift",
    "Tools/AcceptanceController/Sources/reach-acceptance-controller/main.swift",
    "Tools/AcceptanceController/CampaignDriver.swift",
    "Tools/AcceptanceController/Tests/AcceptanceControllerCoreTests/ControllerTests.swift",
    "Tools/AcceptanceController/Tests/AcceptanceControllerCoreTests/PublicationTests.swift",
]

private enum DriverFailure: Error, CustomStringConvertible {
    case stopped(String)
    var description: String { switch self { case .stopped(let value): value } }
}

private func rawNow() -> UInt64 {
    var value = timespec(); clock_gettime(CLOCK_MONOTONIC_RAW, &value)
    return UInt64(value.tv_sec) * 1_000_000_000 + UInt64(value.tv_nsec)
}

private enum Hash {
    private static let k: [UInt32] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]
    static func hex(_ data: Data) -> String {
        var m = Array(data); let bits = UInt64(m.count) * 8; m.append(0x80)
        while m.count % 64 != 56 { m.append(0) }
        m.append(contentsOf: withUnsafeBytes(of: bits.bigEndian, Array.init))
        var s: [UInt32] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
        for o in stride(from: 0, to: m.count, by: 64) {
            var w = [UInt32](repeating: 0, count: 64)
            for i in 0..<16 { let b=o+i*4; w[i]=UInt32(m[b])<<24|UInt32(m[b+1])<<16|UInt32(m[b+2])<<8|UInt32(m[b+3]) }
            for i in 16..<64 { let a=w[i-15],b=w[i-2]; w[i]=w[i-16]&+(ror(a,7)^ror(a,18)^(a>>3))&+w[i-7]&+(ror(b,17)^ror(b,19)^(b>>10)) }
            var a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7]
            for i in 0..<64 { let t1=h&+(ror(e,6)^ror(e,11)^ror(e,25))&+((e&f)^((~e)&g))&+k[i]&+w[i]; let t2=(ror(a,2)^ror(a,13)^ror(a,22))&+((a&b)^(a&c)^(b&c)); h=g;g=f;f=e;e=d&+t1;d=c;c=b;b=a;a=t1&+t2 }
            s[0]&+=a;s[1]&+=b;s[2]&+=c;s[3]&+=d;s[4]&+=e;s[5]&+=f;s[6]&+=g;s[7]&+=h
        }
        return s.map { String(format:"%08x",$0) }.joined()
    }
    static func file(_ path: String) throws -> String { hex(try Data(contentsOf: URL(fileURLWithPath:path), options:.mappedIfSafe)) }
    private static func ror(_ v: UInt32,_ n: UInt32)->UInt32{(v>>n)|(v<<(32-n))}
}

private func canonical(_ object: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}

private func jsonValue<T>(_ value: T?) -> Any { value ?? NSNull() }

private func durableWrite(_ data: Data, _ path: String, exclusive: Bool = true) throws {
    let flags = O_WRONLY|O_CREAT|(exclusive ? O_EXCL : O_TRUNC)|O_NOFOLLOW|O_CLOEXEC
    let fd = open(path, flags, 0o600); guard fd >= 0 else { throw DriverFailure.stopped("open:\(path):\(errno)") }
    defer { close(fd) }
    try data.withUnsafeBytes { raw in
        guard let base=raw.baseAddress else{return}; var n=0
        while n<raw.count { let w=Darwin.write(fd,base.advanced(by:n),raw.count-n); guard w>0 else{throw DriverFailure.stopped("write:\(errno)")}; n+=w }
    }
    guard fsync(fd)==0 else { throw DriverFailure.stopped("fsync-file") }
}

private func fsyncDirectory(_ path: String) throws {
    let fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);guard fd>=0 else{throw DriverFailure.stopped("open-dir")};defer{close(fd)}
    guard fsync(fd)==0 else{throw DriverFailure.stopped("fsync-dir")}
}

private final class Capture: @unchecked Sendable {
    private let lock=NSLock(); private var out=Data(); private var err=Data(); private(set) var overflow=false
    func add(_ data:Data,out isOut:Bool){lock.lock();defer{lock.unlock()};if isOut{if out.count+data.count>16*1024*1024{overflow=true};out.append(data.prefix(max(0,16*1024*1024-out.count)))}else{if err.count+data.count>16*1024*1024{overflow=true};err.append(data.prefix(max(0,16*1024*1024-err.count)))}}
    func value()->(Data,Data,Bool){lock.lock();defer{lock.unlock()};return(out,err,overflow)}
}

private final class DriverStorageMonitor: @unchecked Sendable {
    private let root:String,lock=NSLock(),queue=DispatchQueue(label:"reach.s63.driver-storage")
    private var timer:DispatchSourceTimer?,samples:[[String:Any]]=[],failure:String?
    init(_ root:String){self.root=root}
    func start(){sample();let t=DispatchSource.makeTimerSource(queue:queue);t.schedule(deadline:.now()+.milliseconds(20),repeating:.milliseconds(20));t.setEventHandler{[weak self] in self?.sample()};timer=t;t.resume()}
    func sample(){do{var pending=[root],seen=Set<String>(),physical:Int64=0,logical:Int64=0;while let path=pending.popLast(){var s=stat();guard lstat(path,&s)==0 else{throw DriverFailure.stopped("storage-lstat")};let key="\(UInt64(s.st_dev)):\(UInt64(s.st_ino))";if !seen.insert(key).inserted{continue};physical += Int64(s.st_blocks)*512;logical += max(0,Int64(s.st_size));if(s.st_mode&S_IFMT)==S_IFDIR{for child in try FileManager.default.contentsOfDirectory(atPath:path){pending.append(path+"/"+child)}}};let row:[String:Any]=["at":rawNow(),"logicalBytes":logical,"physicalBytes":physical];lock.lock();samples.append(row);lock.unlock()}catch{lock.lock();if failure==nil{failure=String(describing:error)};lock.unlock()}}
    func snapshot()->[String:Any]{lock.lock();defer{lock.unlock()};let physical=samples.compactMap{$0["physicalBytes"] as? Int64}.max() ?? 0,logical=samples.compactMap{$0["logicalBytes"] as? Int64}.max() ?? 0,times=samples.compactMap{$0["at"] as? UInt64};var gap:UInt64=0;for pair in zip(times,times.dropFirst()){gap=max(gap,pair.1>=pair.0 ? pair.1-pair.0:UInt64.max)};return["current":samples.last ?? [:],"failure":jsonValue(failure),"maximumGapNanoseconds":gap,"observedPeakLogicalBytes":logical,"observedPeakPhysicalBytes":physical,"sampleCount":samples.count]}
    func finish()->([[String:Any]],[String:Any]){timer?.cancel();timer=nil;sample();lock.lock();let copy=samples;lock.unlock();return(copy,snapshot())}
}

private struct ChildResult { let t0:UInt64;let t1:UInt64;let exit:Int32?;let signal:Int32?;let out:Data;let err:Data;let timeout:UInt64?;let term:UInt64?;let kill:UInt64?;let absent:UInt64?;let group:Bool }

private final class Campaign {
    let root:String; let repo:String; let t0:UInt64; let deadline:UInt64; let ledger:String
    let driverHash:String; var ordinal=0; var previousHash=String(repeating:"0",count:64); var sourceEpoch=0; var lastManifest=""
    var resolveCount=0,buildCount=0,testCount=0,runCount=0,verifyCount=0,topCount=0,termCount=0,killCount=0
    var insideControllers=0,insideFixtures=0,insidePublishers=0,outsideActions=0,totalOutput=0
    var stopped:String?; var releasePath:String?; var releaseHash:String?; var releaseManifest:String?; var passingTests=0
    var dRuns:[String:(packet:String,root:String,receipt:String,exit:Int32)]=[:]; var verifierStage=0; let storage:DriverStorageMonitor

    init(root:String) throws {
        self.root=root; repo=FileManager.default.currentDirectoryPath; t0=rawNow(); deadline=t0+7_200_000_000_000
        ledger=root+"/slice-ledger"; try FileManager.default.createDirectory(atPath:ledger,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        driverHash=try Hash.file(repo+"/Tools/AcceptanceController/CampaignDriver.swift");storage=DriverStorageMonitor(root);storage.start()
        let manifest=try sourceManifest();lastManifest=Hash.hex(manifest)
        try durableWrite(manifest,root+"/bootstrap-source-manifest.json")
        let row:[String:Any]=["argv":["xcrun","swift","Tools/AcceptanceController/CampaignDriver.swift","--root",root],"deadline":deadline,"driverSHA256":driverHash,"kind":"BOOTSTRAP","ordinal":0,"previous":previousHash,"rawT0":t0,"sourceManifestSHA256":lastManifest]
        try append(row); print("READY S63 \(t0) \(deadline)");fflush(stdout)
    }

    func sourceManifest() throws -> Data {
        var rows:[[String:Any]]=[]
        for p in sourcePaths { let full=repo+"/"+p;var st=stat();guard lstat(full,&st)==0,(st.st_mode&S_IFMT)==S_IFREG,st.st_nlink==1 else{throw DriverFailure.stopped("source-authority:\(p)")};rows.append(["bytes":Int64(st.st_size),"path":p,"sha256":try Hash.file(full)]) }
        return try canonical(["paths":rows,"version":1])
    }

    func append(_ content:[String:Any]) throws {
        ordinal += 1; var row=content;row["ledgerOrdinal"]=ordinal;row["previousRowSHA256"]=previousHash
        let data=try canonical(row);let hash=Hash.hex(data);try durableWrite(data,ledger+String(format:"/%03d.json",ordinal));try fsyncDirectory(ledger);previousHash=hash
    }

    func refreshSources() throws -> String {
        let data=try sourceManifest();let digest=Hash.hex(data)
        if digest != lastManifest { let newDriver=try Hash.file(repo+"/Tools/AcceptanceController/CampaignDriver.swift");guard newDriver==driverHash else{throw DriverFailure.stopped("driver-source-changed")};guard runCount==0 else{throw DriverFailure.stopped("source-changed-after-d1")};sourceEpoch+=1;lastManifest=digest;passingTests=0;releasePath=nil;releaseHash=nil;releaseManifest=nil }
        return digest
    }

    func runChild(kind:String,argv:[String],work:UInt64,expected:Set<Int32>,testFooter:Bool=false,beforeSpawn:(() throws -> Void)?=nil) throws -> ChildResult {
        guard stopped==nil else{throw DriverFailure.stopped("campaign-stopped")};let now=rawNow();let settle=work+30_000_000_000
        guard now+settle<deadline else{throw DriverFailure.stopped("slice-deadline-refusal")};guard topCount<31 else{throw DriverFailure.stopped("top-command-limit")}
        let manifest=try refreshSources();topCount+=1
        let started:[String:Any]=["argv":argv,"kind":kind,"ordinal":topCount,"rawT0":now,"sourceEpoch":sourceEpoch,"sourceManifestSHA256":manifest,"state":"STARTED","workDeadline":now+work,"settlementDeadline":now+settle,"vector":vector()]
        try append(started);try beforeSpawn?()
        let result=try spawn(argv:argv,workDeadline:now+work,settlementDeadline:now+settle)
        totalOutput += result.out.count+result.err.count
        if result.term != nil{termCount+=1};if result.kill != nil{killCount+=1}
        var footer:[String:Any]?=nil
        if testFooter {
            guard let text=String(data:result.out,encoding:.utf8),let range=text.range(of:"REACH-ACCEPTANCE-TEST-COUNTS/1 ",options:.backwards) else{stopped="missing-test-footer";throw DriverFailure.stopped("missing-test-footer")}
            let tail=text[range.upperBound...].split(separator:"\n",maxSplits:1)[0]
            guard let data=String(tail).data(using:.utf8),let parsed=try JSONSerialization.jsonObject(with:data) as? [String:Any],let c=parsed["controllers"] as? Int,let f=parsed["fixtures"] as? Int,let p=parsed["publishers"] as? Int,c>=0,f>=0,p>=0 else{stopped="malformed-test-footer";throw DriverFailure.stopped("malformed-test-footer")}
            insideControllers+=c;insideFixtures+=f;insidePublishers+=p;footer=parsed
        }
        let code=result.exit ?? -(result.signal ?? 0);let okay=expected.contains(code)
        let terminal:[String:Any]=["exit":code,"expected":okay,"groupAssigned":result.group,"groupAbsentAt":jsonValue(result.absent),"kind":kind,"killSentAt":jsonValue(result.kill),"ordinal":topCount,"rawT0":result.t0,"rawT1":result.t1,"signal":jsonValue(result.signal),"sourceManifestSHA256":manifest,"state":"SETTLED","stderrBytes":result.err.count,"stderrSHA256":Hash.hex(result.err),"stdoutBytes":result.out.count,"stdoutSHA256":Hash.hex(result.out),"termSentAt":jsonValue(result.term),"testFooter":jsonValue(footer),"timeoutDetectedAt":jsonValue(result.timeout),"vector":vector()]
        try append(terminal)
        guard result.group,result.absent != nil,result.t1<=now+settle,totalOutput<=128*1024*1024 else{stopped="top-level-settlement";throw DriverFailure.stopped("top-level-settlement")}
        guard okay else{throw DriverFailure.stopped("child-nonexpected:\(kind):\(code)")}
        return result
    }

    func spawn(argv:[String],workDeadline:UInt64,settlementDeadline:UInt64)throws->ChildResult{
        let p=Process(),op=Pipe(),ep=Pipe(),capture=Capture(),group=DispatchGroup();p.executableURL=URL(fileURLWithPath:argv[0]);p.arguments=Array(argv.dropFirst());p.currentDirectoryURL=URL(fileURLWithPath:repo);p.standardInput=FileHandle.nullDevice;p.standardOutput=op;p.standardError=ep
        var env=["PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":root+"/home","TMPDIR":root+"/tmp","CLANG_MODULE_CACHE_PATH":root+"/module-cache","SWIFTPM_MODULECACHE_OVERRIDE":root+"/module-cache"]
        if let d=ProcessInfo.processInfo.environment["DEVELOPER_DIR"]{env["DEVELOPER_DIR"]=d};p.environment=env
        func drain(_ h:FileHandle,_ isOut:Bool){group.enter();DispatchQueue.global(qos:.utility).async{defer{group.leave()};while true{let d=h.readData(ofLength:32768);if d.isEmpty{return};capture.add(d,out:isOut)}}}
        drain(op.fileHandleForReading,true);drain(ep.fileHandleForReading,false);let start=rawNow();try p.run();let pid=p.processIdentifier;let assigned=setpgid(pid,pid)==0||getpgid(pid)==pid
        var timeout:UInt64?,term:UInt64?,killAt:UInt64?
        while p.isRunning{let n=rawNow();if n>=workDeadline||capture.value().2{timeout=n;term=n;if assigned{_ = Darwin.kill(-pid,SIGTERM)}else{p.terminate()};let edge=min(settlementDeadline,n+10_000_000_000);while p.isRunning&&rawNow()<edge{usleep(10_000)};if p.isRunning{killAt=rawNow();_ = Darwin.kill(assigned ? -pid:pid,SIGKILL)};break};usleep(10_000)}
        p.waitUntilExit();op.fileHandleForWriting.closeFile();ep.fileHandleForWriting.closeFile();_ = group.wait(timeout:.now()+5)
        var absent:UInt64?;while rawNow()<settlementDeadline{if !assigned||(Darwin.kill(-pid,0)==-1&&errno==ESRCH){absent=rawNow();break};usleep(10_000)}
        let captured=capture.value();return ChildResult(t0:start,t1:rawNow(),exit:p.terminationReason == .exit ? p.terminationStatus:nil,signal:p.terminationReason == .uncaughtSignal ? p.terminationStatus:nil,out:captured.0,err:captured.1,timeout:timeout,term:term,kill:killAt,absent:absent,group:assigned)
    }

    func vector()->[String:Any]{["aggregateControlledProcesses":1+topCount+insideControllers+insideFixtures+insidePublishers+outsideActions,"builds":buildCount,"driverLaunches":1,"insideActionFixtures":insideFixtures,"insideControllers":insideControllers,"insidePublishers":insidePublishers,"kills":killCount,"outsideActions":outsideActions,"resolve":resolveCount,"runs":runCount,"settlementWindows":topCount,"storage":storage.snapshot(),"terms":termCount,"tests":testCount,"topCommands":topCount,"verifiers":verifyCount]}

    func resolve() throws {guard resolveCount==0 else{throw DriverFailure.stopped("resolve-limit")};resolveCount+=1;_ = try runChild(kind:"resolve",argv:["/usr/bin/xcrun","swift","package","--package-path","Tools/AcceptanceController","--scratch-path",root+"/resolve","resolve"],work:120_000_000_000,expected:[0])}
    func build(_ release:Bool)throws{guard buildCount<6 else{throw DriverFailure.stopped("build-limit")};buildCount+=1;let dir=root+(release ? "/build-release-\(buildCount)":"/build-debug-\(buildCount)");var args=["/usr/bin/xcrun","swift","build","--package-path","Tools/AcceptanceController","--scratch-path",dir,"--build-tests","-c",release ? "release":"debug"];let r=try runChild(kind:release ? "build-release":"build-debug",argv:args,work:600_000_000_000,expected:[0]);_ = r;if release{guard let found=findExecutable(in:dir) else{throw DriverFailure.stopped("release-executable-missing")};releasePath=found;releaseHash=try Hash.file(found);releaseManifest=lastManifest}}
    func test()throws{guard testCount<8 else{throw DriverFailure.stopped("test-limit")};testCount+=1;let dir=root+"/test-\(testCount)";let r=try runChild(kind:"test",argv:["/usr/bin/xcrun","swift","test","--package-path","Tools/AcceptanceController","--scratch-path",dir,"-c","debug"],work:1_200_000_000_000,expected:[0],testFooter:true);_ = r;passingTests+=1}
    func findExecutable(in root:String)->String?{guard let e=FileManager.default.enumerator(atPath:root)else{return nil};for case let p as String in e where p.hasSuffix("/reach-acceptance-controller")||p=="reach-acceptance-controller"{let f=root+"/"+p;if FileManager.default.isExecutableFile(atPath:f){var s=stat();if lstat(f,&s)==0,(s.st_mode&S_IFMT)==S_IFREG{return f}}};return nil}

    func snapshot(_ cell:String)throws->(String,String){let rows=(try FileManager.default.contentsOfDirectory(atPath:ledger)).sorted().map{["path":$0,"sha256":try! Hash.file(ledger+"/"+$0)]};let data=try canonical(["cell":cell,"ledgerRows":rows,"sourceManifestSHA256":lastManifest,"vector":vector(),"version":1]);let path=root+"/runs/"+cell+"/launch-snapshot.json";try durableWrite(data,path);return(path,Hash.hex(data))}

    func runD(_ cell:String)throws{guard passingTests>=2,let exe=releasePath,let exeHash=releaseHash,releaseManifest==lastManifest else{throw DriverFailure.stopped("qualification-not-frozen")};let expectedOrder=["D1","D2","D3"];guard runCount<3,expectedOrder[runCount]==cell else{throw DriverFailure.stopped("d-order")};runCount+=1
        let runRoot=root+"/runs/"+cell;try FileManager.default.createDirectory(atPath:runRoot,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]);let source=try sourceManifest();let sourcePath=runRoot+"/source-manifest.json";try durableWrite(source,sourcePath)
        let cases=cell=="D1" ? ["ok-a","ok-b"] : (cell=="D2" ? ["ok-a","stop","ok-b"]:["ok-a","timeout","ok-b"]);let packet=runRoot+"/packet",specPath=runRoot+"/spec.json",expected:Int32=cell=="D1" ? 0:20
        let r=try runChild(kind:"run-\(cell.lowercased())",argv:[exe,"run","--scratch",runRoot,"--spec",specPath,"--packet",packet],work:1_500_000_000_000,expected:[expected],beforeSpawn:{let snap=try self.snapshot(cell);let base=rawNow();var actions:[[String:Any]]=[];for(i,c)in cases.enumerated(){let work=base+UInt64((i+1)*5)*1_000_000_000;let actualWork=(cell=="D3"&&i==1) ? base+2_000_000_000:work;actions.append(["allowedReasonCodes":c=="stop" ? ["syntheticStop"]:[],"arguments":["fixture",c],"environment":["REACH_ACTION_ID":"\(cell.lowercased())-\(i)","REACH_ACTION_ORDINAL":"\(i)"],"executable":exe,"expectedKind":c=="stop" ? "stop":"ok","id":"\(cell.lowercased())-\(i)","ordinal":i,"settlementDeadlineNanoseconds":actualWork+6_000_000_000,"workDeadlineNanoseconds":actualWork,"workingDirectory":self.repo])};let spec:[String:Any]=["actions":actions,"executableDigest":exeHash,"launchSnapshotDigest":snap.1,"launchSnapshotPath":snap.0,"packetPath":packet,"runID":UUID().uuidString,"scratchRoot":runRoot,"sourceManifestDigest":Hash.hex(source),"sourceManifestPath":sourcePath,"version":1];try durableWrite(try canonical(spec),specPath)});outsideActions += 2
        guard let receipt=try JSONSerialization.jsonObject(with:r.out) as? [String:Any],let rootDigest=receipt["packetRootDigest"] as? String,let path=receipt["path"] as? String,path==packet else{throw DriverFailure.stopped("receipt-\(cell)")};dRuns[cell]=(packet,rootDigest,Hash.hex(r.out),expected)
    }

    func verify(_ cell:String,mutant:Bool)throws{let order=[("D1",false),("D2",false),("D3",false),("D1",true),("D2",true),("D3",true)];guard verifierStage<order.count,order[verifierStage].0==cell,order[verifierStage].1==mutant,let exe=releasePath,let run=dRuns[cell]else{throw DriverFailure.stopped("verify-order")};verifierStage+=1;verifyCount+=1;var packet=run.packet;let expected:Int32
        if mutant{let parent=root+"/mutants";try FileManager.default.createDirectory(atPath:parent,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]);packet=parent+"/"+cell;try FileManager.default.copyItem(atPath:run.packet,toPath:packet);let outcome=packet+"/outcome.json";let fd=open(outcome,O_WRONLY|O_APPEND|O_CLOEXEC);guard fd>=0 else{throw DriverFailure.stopped("mutant-open")};var newline=UInt8(ascii:"\n");_ = withUnsafePointer(to:&newline){Darwin.write(fd,$0,1)};fsync(fd);close(fd);expected=65}else{expected=0}
        _ = try runChild(kind:mutant ? "verify-mutant-\(cell.lowercased())":"verify-original-\(cell.lowercased())",argv:[exe,"verify","--packet",packet],work:120_000_000_000,expected:[expected])
    }

    func closeCampaign()throws{guard rawNow()+6_000_000_000<deadline,stopped==nil,runCount==3,verifierStage==6,passingTests>=2 else{throw DriverFailure.stopped("close-precondition")};try append(["kind":"CLOSE_STARTED","rawT0":rawNow(),"vector":vector()]);let retained=root+"/retained";try FileManager.default.createDirectory(atPath:retained,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]);if let exe=releasePath{try FileManager.default.copyItem(atPath:exe,toPath:retained+"/reach-acceptance-controller");chmod(retained+"/reach-acceptance-controller",0o700)};try durableWrite(try sourceManifest(),retained+"/source-manifest.json");for name in try FileManager.default.contentsOfDirectory(atPath:root) where name.hasPrefix("build-")||name.hasPrefix("test-")||name=="resolve"||name=="tmp"||name=="module-cache"||name=="home"{try? FileManager.default.removeItem(atPath:root+"/"+name)}
        let finished=storage.finish();try durableWrite(try canonical(["samples":finished.0,"summary":finished.1,"version":1]),retained+"/storage-samples.json");guard (finished.1["failure"] as? NSNull) != nil,(finished.1["maximumGapNanoseconds"] as? UInt64 ?? UInt64.max)<=100_000_000,(finished.1["observedPeakPhysicalBytes"] as? Int64 ?? Int64.max)<=1_073_741_824,(finished.1["observedPeakLogicalBytes"] as? Int64 ?? Int64.max)<=1_073_741_824 else{throw DriverFailure.stopped("storage-bound")}
        let final:[String:Any]=["commandCount":topCount,"kind":"COMMANDS_CLOSED","rawT1":rawNow(),"remaining":["builds":6-buildCount,"runs":8-runCount,"tests":8-testCount,"topCommands":31-topCount,"verifiers":8-verifyCount],"sourceManifestSHA256":lastManifest,"storage":finished.1,"vector":vector()];try append(final);try fsyncDirectory(ledger)
    }
}

guard CommandLine.arguments.count==3,CommandLine.arguments[1]=="--root",CommandLine.arguments[2].hasPrefix("/private/tmp/") else{fputs("usage\n",stderr);Darwin.exit(64)}
let root=CommandLine.arguments[2]
do{
    var st=stat();guard lstat(root,&st)==0,(st.st_mode&S_IFMT)==S_IFDIR,(st.st_mode&0o777)==0o700,st.st_uid==getuid() else{throw DriverFailure.stopped("root-authority")}
    for d in ["home","tmp","module-cache","runs"]{try FileManager.default.createDirectory(atPath:root+"/"+d,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])}
    let campaign=try Campaign(root:root)
    while let line=readLine(){do{switch line{
        case "resolve":try campaign.resolve()
        case "build-debug":try campaign.build(false)
        case "build-release":try campaign.build(true)
        case "test":try campaign.test()
        case "run-d1":try campaign.runD("D1")
        case "run-d2":try campaign.runD("D2")
        case "run-d3":try campaign.runD("D3")
        case "verify-original D1":try campaign.verify("D1",mutant:false)
        case "verify-original D2":try campaign.verify("D2",mutant:false)
        case "verify-original D3":try campaign.verify("D3",mutant:false)
        case "verify-mutant D1":try campaign.verify("D1",mutant:true)
        case "verify-mutant D2":try campaign.verify("D2",mutant:true)
        case "verify-mutant D3":try campaign.verify("D3",mutant:true)
        case "close":try campaign.closeCampaign();print("CLOSED S63 \(rawNow())");fflush(stdout);Darwin.exit(0)
        default:throw DriverFailure.stopped("unknown-command")};print("SETTLED \(line)");fflush(stdout)}catch{fputs("DRIVER-STOP \(error)\n",stderr);fflush(stderr);Darwin.exit(70)}}
    throw DriverFailure.stopped("stdin-eof-before-close")
}catch{fputs("DRIVER-FAILURE \(error)\n",stderr);Darwin.exit(70)}
