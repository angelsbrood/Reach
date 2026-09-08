import Foundation
import Testing
@testable import ReachWire

@Suite struct IndependentWireTests {
    private func raw(_ value:DurableMessage) throws -> RawFrame { var parser=FrameReassembler();return try #require(parser.feed(value.encode(version:2)).first) }
    @Test func profileMustMatchExplicitLocalSelectionBeforeOpen() throws {
        for selected in [DurableWire.profile,DurableWire.independentProfile] {
            let other=selected==DurableWire.profile ? DurableWire.independentProfile : DurableWire.profile
            var state=try DurableNegotiation(selectedDialect:2,modelID:"model",localOptIn:true,expectedProfile:selected)
            _=try state.receive(raw(.capabilities(.init(.init(modelID:"model",profiles:[other])))))
            #expect(throws:(any Error).self) { try state.send(.open(.init(.init(requestID:"open",modelID:"model",profile:selected,durable:true)))) }
            var matching=try DurableNegotiation(selectedDialect:2,modelID:"model",localOptIn:true,expectedProfile:selected)
            _=try matching.receive(raw(.capabilities(.init(.init(modelID:"model",profiles:[selected])))))
            #expect(throws:(any Error).self) { try matching.send(.open(.init(.init(requestID:"open",modelID:"model",profile:other,durable:true)))) }
            _=try matching.send(.open(.init(.init(requestID:"open",modelID:"model",profile:selected,durable:true))))
            #expect(matching.phase == .opening)
        }
        #expect(throws:(any Error).self) { try DurableNegotiation(selectedDialect:2,modelID:"model",localOptIn:true,expectedProfile:"unknown") }
        #expect(Hello(client:"default").versions == [1,0])
        #expect(try DurableNegotiation(modelID:"default").expectedProfile == DurableWire.profile)
    }
}
