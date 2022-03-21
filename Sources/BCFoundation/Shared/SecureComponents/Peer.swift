import Foundation
import CryptoKit
import WolfBase

/// Holds information used to communicate cryptographically with a remote peer.
///
/// Includes the peer's public signing key for verifying signatures created by the
/// peer via EdDSA over Curve25519, and the peer's public public agreement key
/// and salt used for X25519 key agreement.
public struct Peer: CustomStringConvertible, Hashable {
    public let publicSigningKey: PublicSigningKey
    public let publicAgreementKey: PublicAgreementKey
    public let salt: Data
    
    public init(publicSigningKey: PublicSigningKey, publicAgreementKey: PublicAgreementKey, salt: DataProvider? = nil) {
        self.publicSigningKey = publicSigningKey
        self.publicAgreementKey = publicAgreementKey
        self.salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
    }
    
    public var description: String {
        "Peer(signingKey: \(publicSigningKey), agreementKey: \(publicAgreementKey), salt: \(salt.hex)"
    }
}

extension Peer {
    public init(identity: Identity) {
        self.init(publicSigningKey: identity.publicSigningKey, publicAgreementKey: identity.publicAgreementKey, salt: identity.salt)
    }
}

extension Peer {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let signingKey = publicSigningKey.taggedCBOR
        let agreementKey = publicAgreementKey.taggedCBOR
        let salt = CBOR.data(salt)
        
        return CBOR.array([type, signingKey, agreementKey, salt])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.securePeer.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 4,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(signingKeyData) = elements[1],
            let signingKey = PublicSigningKey(taggedCBOR: signingKeyData),
            case let CBOR.data(agreementKeyData) = elements[2],
            let agreementKey = PublicAgreementKey(taggedCBOR: agreementKeyData),
            case let CBOR.data(salt) = elements[3]
        else {
            throw CBORError.invalidFormat
        }
        
        self.init(publicSigningKey: signingKey, publicAgreementKey: agreementKey, salt: salt)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.securePeer.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
