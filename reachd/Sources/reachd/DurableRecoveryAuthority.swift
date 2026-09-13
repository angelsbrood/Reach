import ArgumentParser
import Foundation
import Darwin
import ReachDurableRuntime

/// Explicit qualification dispatch only; no ordinary offer/profile is changed.
struct DurableRecoveryAuthority: ParsableCommand {
    static let configuration=CommandConfiguration(commandName:"durable-recovery-authority",abstract:"Qualify original allocating/preparing authority across a receiver reboot.",subcommands:[Witness.self,Provision.self,Initialize.self,Admit.self,Accept.self,Authenticate.self,Retire.self])
    struct Pair: ParsableArguments {
        @Option(name:.long) var hostReceipt:String
        @Option(name:.long) var hostDigest:String
        @Option(name:.long) var clientReceipt:String
        @Option(name:.long) var clientDigest:String
    }
    struct Witness: ParsableCommand {
        static let configuration=CommandConfiguration(abstract:"Run one owned process-memory qualification witness on controller pipes.")
        func run() throws { try authorityCommand { try RecoveryAuthorityRuntime.witness() } }
    }
    struct Provision: ParsableCommand {
        @Option(name:.long) var publicModel:String
        @Option(name:.long) var request:String
        @Option(name:.long) var output:String
        func run() throws {
            try authorityCommand { try RecoveryAuthorityRoots.provision(originals:RecoveryAuthorityChannel.read(),publicModel:publicModel,request:request,output:output) }
        }
    }
    struct Initialize: ParsableCommand {
        static let configuration=CommandConfiguration(commandName:"init",abstract:"Create one fresh v4 role and retain its original ownership receipt.")
        @Option(name:.long) var root:String
        @Option(name:.long) var role:String
        @Option(name:.long) var configuration:String
        @Option(name:.long) var ownerReceipt:String
        @Option(name:.long) var unlockSecretFd:Int32
        func run() throws {
            try authorityCommand {
                let digest=try RecoveryAuthorityRoots.initialize(root:root,role:role,configuration:configuration,receipt:ownerReceipt,secretDescriptor:unlockSecretFd)
                struct Result:Encodable { let stage="ready"; let role:String, ownerReceiptDigest:String }
                try RecoveryAuthorityChannel.write(Result(role:role,ownerReceiptDigest:digest))
            }
        }
    }
    struct Admit: ParsableCommand {
        @OptionGroup var pair:Pair
        @Option(name:.long) var unlockSecretFd:Int32
        @Option(name:.long) var model:String
        @Option(name:.long) var request:String
        @Option(name:.long) var export:String
        func run() throws {
            try authorityCommand { try RecoveryAuthorityRuntime.admit(hostReceipt:pair.hostReceipt,hostDigest:pair.hostDigest,
                clientReceipt:pair.clientReceipt,clientDigest:pair.clientDigest,secretDescriptor:unlockSecretFd,model:model,request:request,export:export) }
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
            try authorityCommand { try RecoveryAuthorityRuntime.accept(hostReceipt:pair.hostReceipt,hostDigest:pair.hostDigest,
                clientReceipt:pair.clientReceipt,clientDigest:pair.clientDigest,secretDescriptor:unlockSecretFd,export:export,
                originalIssuer:issuer,successfulExportDigest:successfulExportDigest) }
        }
    }
    struct Authenticate: ParsableCommand {
        @Option(name:.long) var ownerReceipt:String
        @Option(name:.long) var expectedReceiptDigest:String
        @Option(name:.long) var unlockSecretFd:Int32
        @Option(name:.long) var blockMilliseconds:Int = 0
        @Flag(name:.long) var observeWitness=false
        func run() throws {
            try authorityCommand { try RecoveryAuthorityRuntime.authenticate(receipt:ownerReceipt,expectedDigest:expectedReceiptDigest,
                secretDescriptor:unlockSecretFd,blockMilliseconds:blockMilliseconds,observeWitness:observeWitness) }
        }
    }
    struct Retire: ParsableCommand {
        @Option(name:.long) var ownerReceipt:String
        @Option(name:.long) var expectedReceiptDigest:String
        @Option(name:.long) var unlockSecretFd:Int32?
        @Flag(name:.long) var afterBoot=false
        func run() throws {
            try authorityCommand {
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
private func authorityCommand(_ body: () throws -> Void) throws {
    do { try body() }
    catch {
        // Content-free, bounded refusal; framework descriptions may contain content.
        var detail=String(describing:type(of:error))
        if let error=error as? AuthorityError { detail += ":"+error.rawValue }
        fputs("durable-recovery-authority refused (\(detail.prefix(120))).\n",stderr)
        throw ExitCode.failure
    }
}
