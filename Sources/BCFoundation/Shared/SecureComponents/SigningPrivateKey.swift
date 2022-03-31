import Foundation
import CryptoKit
import WolfBase

public struct SigningPrivateKey: CustomStringConvertible, Hashable {
    public let data: Data

    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }

    public init() {
        self.data = SecureRandomNumberGenerator.shared.data(count: 32)
    }
    
    public func ecdsaSign(_ message: DataProvider) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let sig = privateKey.ecdsaSign(message: message.providedData)
        return Signature(ecdsaData: sig)!
    }

    public func schnorrSign(_ message: DataProvider, tag: DataProvider = Data()) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let sig = privateKey.schnorrSign(message: message.providedData, tag: tag.providedData)
        return Signature(schnorrData: sig, tag: tag)!
    }
    
    public var ecdsaPublicKey: SigningPublicKey {
        let privateKey = ECPrivateKey(data)!
        let publicKey = privateKey.public
        return SigningPublicKey(ecdsaData: publicKey.data)!
    }
    
    public var schnorrPublicKey: SigningPublicKey {
        let privateKey = ECPrivateKey(data)!
        let xOnlyPublicKey = privateKey.xOnlyPublic
        return SigningPublicKey(schnorrData: xOnlyPublicKey.data)!
    }
    
    public var description: String {
        "PrivateSigningKey(\(data))"
    }
}

extension SigningPrivateKey {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let key = CBOR.data(self.data)
        return CBOR.array([type, key])
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.signingPrivateKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 2,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(data) = elements[1],
            let key = SigningPrivateKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.signingPrivateKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
