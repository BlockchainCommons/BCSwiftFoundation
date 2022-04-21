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

    public func schnorrSign(_ message: DataProvider, tag: DataProvider? = nil) -> Signature {
        let privateKey = ECPrivateKey(data)!
        let tag = tag ?? Data()
        let sig = privateKey.schnorrSign(message: message.providedData, tag: tag.providedData)
        return Signature(schnorrData: sig, tag: tag)!
    }
    
    public var ecdsaPublicKey: SigningPublicKey {
        SigningPublicKey(ECPrivateKey(data)!.public)
    }
    
    public var schnorrPublicKey: SigningPublicKey {
        SigningPublicKey(ECPrivateKey(data)!.xOnlyPublic)
    }
    
    public var description: String {
        "PrivateSigningKey(\(data))"
    }
}

extension SigningPrivateKey {
    public var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.signingPrivateKey, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR,
            let key = SigningPrivateKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.signingPrivateKey, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SigningPrivateKey: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
