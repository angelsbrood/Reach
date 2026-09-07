import Foundation
import Darwin
import DurableRootKeys
import DurableStoreBootstrap
import WireAdapterContract

do {
    let config=try WireLane.control()
    guard config.action=="control",let workers=config.workers else { throw BootstrapError.invalid }
    _=try WireFixture.base();_=try WireFixture.access(workers)
    try OwnedFileKeychain.disableInteraction()
    let initial=try KeychainMetadata.read()
    var container:OwnedFileKeychain?,owned=Set<String>()
    try WireLane.write(.init("ready"))
    while true {
        let request=try WireLane.control()
        do {
            var result=WireControl("ok")
            switch request.action {
            case "create":
                guard container==nil,request.slot=="primary",let password=request.password else { throw BootstrapError.invalid }
                let path=try WireFixture.container()
                container=try OwnedFileKeychain.create(at:path,password:password);owned.insert(path)
                try RootKeyCodec.require(KeychainMetadata.read().preserves(initial,owned:owned));result.metadataPreserved=true
            case "cleanup":
                if let created=container { try created.deleteOwned();container=nil }
                let final=try KeychainMetadata.read();try RootKeyCodec.require(final==initial && final.excludes(owned))
                result.metadataPreserved=true;result.registrationAbsent=true
            case "close":
                guard container==nil else { throw BootstrapError.invalid };try WireLane.write(.init("closed"));exit(0)
            default:throw BootstrapError.invalid
            }
            try WireLane.write(result)
        } catch { try WireLane.write(.failure(error)) }
    }
} catch { var r=WireControl.failure(error);r.action="unavailable";try? WireLane.write(r);exit(1) }
