import Foundation
import CryptoKit

/// A Curve25519 private key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
public struct PrivateAgreementKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        self.rawValue = rawValue
    }
    
    public init() {
        self.rawValue = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
    }
    
    public var description: String {
        "PrivateAgreementKey\(rawValue)"
    }

    public var cryptoKitForm: Curve25519.KeyAgreement.PrivateKey {
        try! .init(rawRepresentation: rawValue)
    }
}

extension PrivateAgreementKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.privateAgreementKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PrivateAgreementKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.privateAgreementKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
