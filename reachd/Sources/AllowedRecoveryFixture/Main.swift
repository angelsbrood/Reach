import ArgumentParser
import Foundation
import Darwin
import ReachDurableRuntime

/// Explicit qualification dispatch only; no ordinary offer/profile is changed.
@main
struct AllowedRecoveryFixtureCommand: ParsableCommand {
    static let configuration=CommandConfiguration(commandName:"reach-allowed-recovery-fixture",abstract:"Prescribed S104 state-model allowed-route qualification only.",subcommands:[MakeFixture.self,Witness.self,PrepareFixture.self,ProbeAllowedFixture.self,Provision.self,Initialize.self,Admit.self,Accept.self,Run.self,Retire.self])
    struct MakeFixture: ParsableCommand {
        @Option(name:.long) var model:String
        @Option(name:.long) var variant:String = "success"
        func run() throws { try nativeCommand { try S104Fixture.write(at:model,variant:variant) } }
    }
    struct Pair: ParsableArguments {
        @Option(name:.long) var hostReceipt:String
        @Option(name:.long) var hostDigest:String
        @Option(name:.long) var clientReceipt:String
        @Option(name:.long) var clientDigest:String
    }
    struct Witness: ParsableCommand {
        static let configuration=CommandConfiguration(abstract:"Run one owned process-memory qualification witness on controller pipes.")
        func run() throws { try nativeCommand { try RecoveryAuthorityRuntime.witness() } }
    }
    struct Provision: ParsableCommand {
        @Option(name:.long) var publicModel:String
        @Option(name:.long) var model:String
        @Option(name:.long) var prepared:String
        @Option(name:.long) var request:String
        @Option(name:.long) var output:String
        func run() throws {
            try nativeCommand { try NativeRecoveryRoots.provision(originals:RecoveryAuthorityChannel.read(),publicModel:publicModel,request:request,model:model,prepared:prepared,output:output,fixture:S104Fixture.factory) }
        }
    }
    struct Initialize: ParsableCommand {
        static let configuration=CommandConfiguration(commandName:"init",abstract:"Create one fresh v5 role and retain its original ownership receipt.")
        @Option(name:.long) var root:String
        @Option(name:.long) var role:String
        @Option(name:.long) var configuration:String
        @Option(name:.long) var ownerReceipt:String
        @Option(name:.long) var unlockSecretFd:Int32
        func run() throws {
            try nativeCommand {
                let digest=try NativeRecoveryRoots.initialize(root:root,role:role,configuration:configuration,receipt:ownerReceipt,secretDescriptor:unlockSecretFd,fixture:S104Fixture.factory)
                struct Result:Encodable { let stage="ready"; let role:String, ownerReceiptDigest:String }
                try RecoveryAuthorityChannel.write(Result(role:role,ownerReceiptDigest:digest))
            }
        }
    }
    struct Admit: ParsableCommand {
        @OptionGroup var pair:Pair
        @Option(name:.long) var unlockSecretFd:Int32
        @Option(name:.long) var request:String
        @Option(name:.long) var export:String
        func run() throws {
            try nativeCommand { try NativeRecoveryRuntime.admit(hostReceipt:pair.hostReceipt,hostDigest:pair.hostDigest,
                clientReceipt:pair.clientReceipt,clientDigest:pair.clientDigest,secretDescriptor:unlockSecretFd,request:request,export:export,fixture:S104Fixture.factory) }
        }
    }
    struct Accept: ParsableCommand {
        @OptionGroup var pair:Pair
        @Option(name:.long) var unlockSecretFd:Int32
        @Option(name:.long) var export:String
        @Option(name:.long) var originalIssuer:String
        @Option(name:.long) var successfulExportDigest:String
        func run() throws {
            guard let issuer=Data(base64Encoded:originalIssuer), issuer.count == 32 else { throw ValidationError("Expected the original host issuer public key.") }
            try nativeCommand { try NativeRecoveryRuntime.accept(hostReceipt:pair.hostReceipt,hostDigest:pair.hostDigest,
                clientReceipt:pair.clientReceipt,clientDigest:pair.clientDigest,secretDescriptor:unlockSecretFd,export:export,
                originalIssuer:issuer,successfulExportDigest:successfulExportDigest,fixture:S104Fixture.factory) }
        }
    }
    struct PrepareFixture: ParsableCommand {
        @Option(name:.long) var model:String
        @Option(name:.long) var request:String
        @Option(name:.long) var operation:String
        @Option(name:.long) var output:String
        @Option(name:.long) var publicModel:String
        func run() throws { try nativeCommand { try NativeRecoveryRuntime.prepareFixture(model:model,request:request,operation:operation,output:output,publicModel:publicModel,fixture:S104Fixture.factory) } }
    }
    struct ProbeAllowedFixture: ParsableCommand {
        @Option(name:.long) var model:String
        @Option(name:.long) var prepared:String
        @Option(name:.long) var report:String
        func run() throws { try nativeCommand { try NativeRecoveryRuntime.probeAllowedFixture(model:model,prepared:prepared,report:report,fixture:S104Fixture.factory) } }
    }
    struct Run: ParsableCommand {
        @OptionGroup var pair:Pair
        @Option(name:.long) var hostSecretFd:Int32
        @Option(name:.long) var clientSecretFd:Int32
        @Flag(name:.long) var original=false
        @Option(name:.long) var stopAfterCalls:Int = 0
        @Flag(name:.long) var leaveHostAhead=false
        @Flag(name:.long) var stopWithPendingGuided=false
        @Option(name:.long) var requiredBoundary:String = "none"
        @Option(name:.long) var allowedBoundary:String = "none"
        @Flag(name:.long) var duplicateExact=false
        @Option(name:.long) var report:String
        @Option(name:.long) var fault:String = "none"
        func run() throws {
            try nativeCommand { try NativeRecoveryRuntime.run(hostReceipt:pair.hostReceipt,hostDigest:pair.hostDigest,
                clientReceipt:pair.clientReceipt,clientDigest:pair.clientDigest,hostSecret:hostSecretFd,clientSecret:clientSecretFd,
                original:original,stopAfterCalls:stopAfterCalls,leaveHostAhead:leaveHostAhead,report:report,fault:fault,stopWithPendingGuided:stopWithPendingGuided,requiredBoundary:requiredBoundary,duplicateExact:duplicateExact,allowedBoundary:allowedBoundary,fixture:S104Fixture.factory) }
        }
    }
    struct Retire: ParsableCommand {
        @Option(name:.long) var ownerReceipt:String
        @Option(name:.long) var expectedReceiptDigest:String
        @Option(name:.long) var unlockSecretFd:Int32?
        @Flag(name:.long) var afterBoot=false
        func run() throws {
            try nativeCommand {
                let report:IndependentRetirementReport
                if afterBoot {
                    report=try IndependentAfterBootRetirement.retire(receipt:ownerReceipt,expectedDigest:expectedReceiptDigest,secretDescriptor:unlockSecretFd)
                } else {
                    guard unlockSecretFd == nil else { throw ValidationError("Use the original unlocked same-boot container or the explicit after-boot path.") }
                    report=try IndependentRoleLifecycle.retire(receipt:ownerReceipt,expectedDigest:expectedReceiptDigest)
                }
                try RecoveryAuthorityChannel.write(report)
            }
        }
    }
}
private func nativeCommand(_ body: () throws -> Void) throws {
    do { try body() }
    catch {
        // Content-free, bounded refusal; framework descriptions may contain content.
        var detail=String(describing:type(of:error))
        if let error=error as? AuthorityError { detail += ":"+error.rawValue }
        fputs("durable-native-recovery refused (\(detail.prefix(120))).\n",stderr)
        throw ExitCode.failure
    }
}
