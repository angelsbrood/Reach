import ArgumentParser
import Foundation
import Darwin
import ReachDurableRuntime

struct DurableLocal:ParsableCommand {
    static let configuration=CommandConfiguration(commandName:"durable-local",abstract:"Explicit local durable generation with a selected Llama profile.",subcommands:[Initialize.self,Begin.self,Recover.self,Cancel.self])
    struct Initialize:ParsableCommand {
        static let configuration=CommandConfiguration(commandName:"init",abstract:"Create a fresh private root and hold its disposable Keychain cleanup authority until signalled.")
        @Option(name:.long) var root:String
        @Option(name:.long,help:"Owner-only directory containing the selected local artifacts.") var model:String
        func run() throws {
            let stop=LocalStop()
            do {
                try LocalDurableRuntime.withCPU {
                    let owner=try LocalRuntimeOwner(root:root,modelSource:model)
                    print("{\"stage\":\"ready\",\"backupExcluded\":\(owner.backupExcluded)}");fflush(stdout)
                    while true {
                        stop.wait()
                        do { try owner.retire();print("{\"stage\":\"retired\"}");fflush(stdout);break }
                        catch { localDiagnostic(error);print("{\"stage\":\"cleanup-blocked\"}");fflush(stdout) }
                    }
                }
            } catch { localDiagnostic(error);throw ExitCode.failure }
        }
    }
    struct Begin:ParsableCommand {
        static let configuration=CommandConfiguration(abstract:"Begin one request in an explicitly initialized root.")
        @Option(name:.long) var root:String
        @Option(name:.long,help:"Owner-only JSON request file.") var request:String
        @Option(name:.long,help:"Write a bounded diagnostic report to a fresh owner-only file.") var report:String?
        @Flag(name:.long,help:"Print boundary progress for local observation.") var progress=false
        func run() throws { try runLocal(root:root,request:request,report:report,progress:progress,cancel:false) }
    }
    struct Recover:ParsableCommand {
        static let configuration=CommandConfiguration(abstract:"Load original authority and continue selected encrypted state.")
        @Option(name:.long) var root:String
        @Option(name:.long) var report:String?
        @Flag(name:.long) var progress=false
        func run() throws { try runLocal(root:root,request:nil,report:report,progress:progress,cancel:false) }
    }
    struct Cancel:ParsableCommand {
        static let configuration=CommandConfiguration(abstract:"Retire local generation with an outer cancellation disposition.")
        @Option(name:.long) var root:String
        @Option(name:.long) var report:String?
        func run() throws { try runLocal(root:root,request:nil,report:report,progress:false,cancel:true) }
    }
}
private final class LocalStop:@unchecked Sendable {
    private let condition=NSCondition()
    private var signalled=false
    private var sources:[DispatchSourceSignal]=[]
    init() {
        for value in [SIGINT,SIGTERM] {
            signal(value,SIG_IGN)
            let source=DispatchSource.makeSignalSource(signal:value,queue:.global())
            source.setEventHandler { [weak self] in guard let self else { return };self.condition.lock();self.signalled=true;self.condition.broadcast();self.condition.unlock() }
            source.resume();sources.append(source)
        }
    }
    var requested:Bool { condition.lock();defer { condition.unlock() };return signalled }
    func wait() { condition.lock();while !signalled { condition.wait() };signalled=false;condition.unlock() }
    deinit { for source in sources { source.cancel() } }
}
private func localDiagnostic(_ error:Error) {
    // Error content can include a request/schema/path. Keep that content out of
    // the default diagnostic; the report shows only actual retained state.
    fputs("durable-local stopped (\(String(describing:type(of:error)).prefix(96))).\n",stderr)
}
private func runLocal(root:String,request:String?,report:String?,progress:Bool,cancel:Bool) throws {
    let stop=LocalStop()
    do {
        try LocalDurableRuntime.withCPU {
            let runtime=try LocalDurableRuntime(root:root,allowBegin:request != nil);defer { runtime.close() }
            do {
                if let request { try runtime.begin(LocalDurableRuntime.request(from:request)) }
                else { try runtime.recover() }
                if cancel { try runtime.cancel() }
                else {
                    while !runtime.terminal && !stop.requested {
                        try runtime.step()
                        if progress {
                            let state=try runtime.report(stage:"progress")
                            print("{\"stage\":\"progress\",\"nativeCalls\":\(state.nativeCalls),\"high\":\(state.high),\"terminal\":\(state.terminal)}");fflush(stdout)
                        }
                    }
                }
                let state=try runtime.report(stage:cancel ? "cancelled" : (runtime.terminal ? "settled" : "stopped"))
                try emit(state,to:report)
            } catch {
                if let state=try? runtime.report(stage:"error") { try? emit(state,to:report) }
                throw error
            }
        }
    } catch { localDiagnostic(error);throw ExitCode.failure }
}
private func emit(_ report:LocalRuntimeReport,to path:String?) throws {
    let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]
    let bytes=try encoder.encode(report)
    try LocalDurableRuntime.writeReport(bytes,to:path)
}
