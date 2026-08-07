import CryptoKit
import Foundation
import Testing
@testable import ReachIdentity

@Suite struct SigningKeyTests {
    /// The predicate, stated on bytes rather than on luck.
    @Test func aLeadingZeroIsTheWholeTest() {
        #expect(!SigningKey.survivesPKCS12(scalar: Data([0x00, 0x46, 0x2D])))
        #expect(SigningKey.survivesPKCS12(scalar: Data([0x46, 0x2D, 0x67])))
        // Two leading zeroes shorten the encoding by two; the same test catches
        // them, because anything with a leading zero starts with one.
        #expect(!SigningKey.survivesPKCS12(scalar: Data([0x00, 0x00, 0x46])))
        // An empty scalar is not a key, but `first` is nil and must not read as
        // zero — the guard says "known good", not "not known bad".
        #expect(SigningKey.survivesPKCS12(scalar: Data()))
    }

    /// Sized to have caught the defect rather than to look thorough: one scalar
    /// in 256 leads with a zero, so 3000 mints expect ~11.7 of them and the
    /// unguarded `P256.Signing.PrivateKey()` would fail this run with
    /// probability 1 - e^-11.7, about 99.999%. A handful of mints would prove
    /// nothing at all, which is how this survived so long as a rate.
    @Test func mintNeverReturnsAKeyPKCS12WouldShorten() {
        var minted = 0
        for _ in 0 ..< 3000 {
            let key = SigningKey.mint()
            let scalar = key.rawRepresentation
            #expect(scalar.count == 32, "P-256 rawRepresentation is the padded scalar")
            #expect(scalar.first != 0, "minted a scalar LibreSSL would write 31 bytes wide")
            minted += 1
        }
        #expect(minted == 3000)
    }
}
