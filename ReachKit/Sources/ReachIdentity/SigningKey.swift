import CryptoKit
import Foundation

/// Minting P-256 signing keys that survive the PKCS#12 round trip.
///
/// ⚠️ **This is the whole of `IdentityError.pkcs12EmptyItemList`**, which was
/// carried for days as an unexplained macOS defect measured at "0.40% per
/// materialization". 0.40% is 1-in-256, and 1-in-256 is P(the scalar's leading
/// byte is zero).
///
/// `IdentityMaterializer.viaPKCS12` is the *production* path on the daemon —
/// `SecItemAdd` wants an entitlement a bare SwiftPM executable does not carry —
/// and it hands the key to `/usr/bin/openssl` (LibreSSL) as PEM. LibreSSL
/// re-encodes the scalar through a BIGNUM, whose minimal encoding drops leading
/// zeroes, so the archive carries a **31-byte** SEC1 `privateKey` OCTET STRING
/// where the input had 32:
///
///     handed to openssl   04 20  00 46 2D 67 …   32 octets, correctly padded
///     written to the p12  04 1F     46 2D 67 …   31 octets, the zero gone
///
/// `SecPKCS12Import` then returns `errSecSuccess` with an **empty item list**:
/// the archive parses, and no identity can be assembled from a short scalar.
///
/// Measured 7 Aug — two arms, one variable, everything else held to the path
/// above: **12 of 12** leading-zero keys returned the empty list, **40 of 40**
/// others imported. Of the 20 failure archives `viaPKCS12` had kept on disk,
/// 19 carry a leading-zero scalar.
///
/// Two older findings survive this and should not be re-opened. Retrying the
/// *import* is still useless, and now for a stated reason rather than an
/// observed one: the bytes are short, so they fail identically however many
/// times they are re-read. And it was never the archive being *malformed* —
/// LibreSSL reads its own output back perfectly well. It is well-formed and
/// one octet too thin.
public enum SigningKey {
    /// A signing key whose scalar is full width, so LibreSSL cannot shorten it.
    ///
    /// Costs one extra keygen 0.4% of the time. The excluded scalars are a
    /// uniform 1-in-256 slice rather than a structured one, so the loss is
    /// log2(256/255) ≈ 0.006 bits — the same trick, and the same arithmetic,
    /// as rejection-sampling a scalar into range in the first place.
    public static func mint() -> P256.Signing.PrivateKey {
        while true {
            let key = P256.Signing.PrivateKey()
            if survivesPKCS12(scalar: key.rawRepresentation) { return key }
        }
    }

    /// Whether a private scalar reaches macOS intact through a PKCS#12 archive
    /// written by LibreSSL. `rawRepresentation` is the curve-width big-endian
    /// scalar, zero-padded; a leading zero is exactly what gets dropped.
    ///
    /// Two leading zeroes (1-in-65536) shorten it by two and are covered by the
    /// same test — any scalar with a leading zero anywhere begins with one.
    public static func survivesPKCS12(scalar: Data) -> Bool {
        scalar.first != 0
    }
}
