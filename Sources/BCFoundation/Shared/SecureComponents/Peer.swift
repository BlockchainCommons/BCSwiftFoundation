import Foundation
import CryptoKit

public struct Peer: CustomStringConvertible, Hashable {
    public let signingPublicKey: PublicSigningKey
    public let agreementPublicKey: PublicAgreementKey
    public let salt: Data
    
    public init(signingPublicKey: PublicSigningKey, agreementPublicKey: PublicAgreementKey, salt: DataProvider? = nil) {
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
    }
    
    public var description: String {
        "Peer(signingKey: \(signingPublicKey), agreementKey: \(agreementPublicKey), salt: \(salt.hex)"
    }
}

extension Peer {
    public init(identity: Identity) {
        self.init(signingPublicKey: identity.signingPublicKey, agreementPublicKey: identity.agreementPublicKey, salt: identity.salt)
    }
}

extension Peer {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let signingKey = signingPublicKey.taggedCBOR
        let agreementKey = agreementPublicKey.taggedCBOR
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
        
        self.init(signingPublicKey: signingKey, agreementPublicKey: agreementKey, salt: salt)
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
