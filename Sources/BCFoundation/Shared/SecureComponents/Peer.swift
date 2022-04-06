import Foundation
import CryptoKit
import WolfBase

/// Holds information used to communicate cryptographically with a remote peer.
///
/// Includes the peer's public signing key for verifying signatures, and
/// the peer's public agreement key and salt used for X25519 key agreement.
public struct Peer: CustomStringConvertible, Hashable {
    public let signingPublicKey: SigningPublicKey
    public let agreementPublicKey: AgreementPublicKey
    
    public init(signingPublicKey: SigningPublicKey, agreementPublicKey: AgreementPublicKey) {
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }
    
    public var description: String {
        "Peer(signingKey: \(signingPublicKey), agreementKey: \(agreementPublicKey)"
    }
}

extension Peer {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let signingKey = signingPublicKey.taggedCBOR
        let agreementKey = agreementPublicKey.taggedCBOR
        
        return CBOR.array([type, signingKey, agreementKey])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.peer.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 3,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(signingKeyData) = elements[1],
            let signingKey = SigningPublicKey(taggedCBOR: signingKeyData),
            case let CBOR.data(agreementKeyData) = elements[2],
            let agreementKey = AgreementPublicKey(taggedCBOR: agreementKeyData)
        else {
            throw CBORError.invalidFormat
        }
        
        self.init(signingPublicKey: signingKey, agreementPublicKey: agreementKey)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.peer.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension Peer {
    public var ur: UR {
        return try! UR(type: URType.peer.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.peer.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
}
