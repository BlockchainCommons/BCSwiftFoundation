import Foundation
import CryptoKit
import WolfBase
import URKit

/// Holds information used to communicate cryptographically with a remote entity.
///
/// Includes the entity's public signing key for verifying signatures, and
/// the entity's public agreement key and salt used for X25519 key agreement.
public struct PublicKeyBase: CustomStringConvertible, Hashable {
    public let signingPublicKey: SigningPublicKey
    public let agreementPublicKey: AgreementPublicKey
    
    public init(signingPublicKey: SigningPublicKey, agreementPublicKey: AgreementPublicKey) {
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }
    
    public var description: String {
        "PublicKeyBase(signingKey: \(signingPublicKey), agreementKey: \(agreementPublicKey)"
    }
}

extension PublicKeyBase {
    public var untaggedCBOR: CBOR {
        [signingPublicKey.taggedCBOR, agreementPublicKey.taggedCBOR]
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.publicKeyBase.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2
        else {
            throw CBORError.invalidFormat
        }
        
        let signingKey = try SigningPublicKey(taggedCBOR: elements[0])
        let agreementKey = try AgreementPublicKey(taggedCBOR: elements[1])

        self.init(signingPublicKey: signingKey, agreementPublicKey: agreementKey)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.publicKeyBase.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension PublicKeyBase {
    public var ur: UR {
        return try! UR(type: URType.publicKeyBase.type, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.publicKeyBase.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
}

extension PublicKeyBase: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension PublicKeyBase: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> PublicKeyBase {
        try PublicKeyBase(taggedCBOR: cbor)
    }
}
