import Foundation
import CryptoKit

/// A Curve25519 public key used for X25519 key agreement.
public struct PublicAgreementKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        self.rawValue = rawValue
    }
    
    public init(_ privateKey: PrivateAgreementKey) {
        self.rawValue = privateKey.cryptoKitForm.publicKey.rawRepresentation
    }
    
    public var description: String {
        "PublicAgreementKey\(rawValue.hex)"
    }
    
    public var cryptoKitForm: Curve25519.KeyAgreement.PublicKey {
        try! .init(rawRepresentation: rawValue)
    }
}

extension PublicAgreementKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.publicAgreementKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PublicAgreementKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.publicAgreementKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
