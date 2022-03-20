import Foundation
import CryptoKit

/// A Curve25519 private key used to create cryptographic signatures.
///
/// Implements EdDSA signature over Curve25519.
///
/// https://datatracker.ietf.org/doc/html/rfc8032
///
/// Note: “CryptoKit implementation of the algorithm employs randomization to generate a different signature on every call, even for the same data and key, to guard against side-channel attacks.”
public struct PrivateSigningKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data

    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }

    public init() {
        self.rawValue = Curve25519.Signing.PrivateKey().rawRepresentation
    }
    
    public func sign(data: DataProvider) -> Signature {
        return try! Signature(rawValue: cryptoKitForm.signature(for: data.providedData))!
    }
    
    public var description: String {
        "PrivateSigningKey(\(rawValue))"
    }
    
    var cryptoKitForm: Curve25519.Signing.PrivateKey {
        try! .init(rawRepresentation: rawValue)
    }
}

extension PrivateSigningKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.privateSigningKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PrivateSigningKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.privateSigningKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
