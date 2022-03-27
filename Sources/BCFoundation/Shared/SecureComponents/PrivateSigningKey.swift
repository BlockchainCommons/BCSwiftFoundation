import Foundation
import CryptoKit
import WolfBase

/// An private key for use in creating Schnorr signatures.
public struct PrivateSigningKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data

    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }

    public init() {
        self.rawValue = SecureRandomNumberGenerator.shared.data(count: 32)
    }
    
    public func sign(_ data: DataProvider, tag: DataProvider = Data()) -> Signature {
        let privateKey = ECPrivateKey(rawValue)!
        let sig = privateKey.schnorrSign(message: data.providedData, tag: tag.providedData)
        return Signature(data: sig, tag: tag)!
    }
    
    public var publicKey: PublicSigningKey {
        let privateKey = ECPrivateKey(rawValue)!
        let xOnlyPublicKey = privateKey.xOnlyPublic
        return PublicSigningKey(rawValue: xOnlyPublicKey.data)!
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
