import Foundation
import CryptoKit
import WolfBase

/// A Curve25519 public key used to verify cryptographic signatures.
public struct PublicSigningKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public init(_ privateKey: PrivateSigningKey) {
        self.rawValue = privateKey.cryptoKitForm.publicKey.rawRepresentation
    }
    
    public var description: String {
        "PublicSigningKey(\(rawValue.hex))"
    }
    
    var cryptoKitForm: Curve25519.Signing.PublicKey {
        try! .init(rawRepresentation: rawValue)
    }
    
    public func isValidSignature(_ signature: Signature, for data: DataProvider) -> Bool {
        cryptoKitForm.isValidSignature(signature.rawValue, for: data.providedData)
    }
}

extension PublicSigningKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.publicSigningKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PublicSigningKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.publicSigningKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
