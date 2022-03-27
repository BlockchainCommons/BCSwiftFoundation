import Foundation
import CryptoKit
import WolfBase

/// A x-only public key used to verify Schnorr signatures.
public struct PublicSigningKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public var description: String {
        "PublicSigningKey(\(rawValue.hex))"
    }
    
    public func isValidSignature(_ signature: Signature, for message: DataProvider) -> Bool {
        let key = ECXOnlyPublicKey(rawValue)!
        return key.schnorrVerify(signature: signature.data, tag: signature.tag, message: message)
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
