import Foundation
import CryptoKit
import WolfBase

/// Types can conform to `IdentityDataProvider` to indicate that they will provide
/// unique data from which keys for signing and encryption can be derived.
///
/// Conforming types include `Data`, `Seed`, `HDKey`, and `Password`.
public protocol IdentityDataProvider {
    var identityData: Data { get }
}

extension Data: IdentityDataProvider {
    public var identityData: Data {
        self
    }
}

extension Seed: IdentityDataProvider {
    public var identityData: Data {
        data
    }
}

extension HDKey: IdentityDataProvider {
    public var identityData: Data {
        keyData
    }
}

/// Holds unique data from which keys for signing and encryption can be derived and
/// a field of random salt used in the key derivation process.
///
/// Derivation is performed used HKDF-SHA512.
///
/// https://datatracker.ietf.org/doc/html/rfc5869
public struct Identity {
    public let data: Data
    public let salt: Data
    
    public init(_ provider: IdentityDataProvider, salt: DataProvider? = nil) {
        let salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
        self.data = provider.identityData
        self.salt = salt
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))
    }
    
    public var signingPrivateKey: SigningPrivateKey {
        return .init(HKDF<SHA512>.deriveKey(inputKeyMaterial: .init(data: data), salt: salt, info: "signing".utf8Data, outputByteCount: 32)
            .withUnsafeBytes { Data($0) })!
    }
    
    public var agreementPrivateKey: AgreementPrivateKey {
        return .init(HKDF<SHA512>.deriveKey(inputKeyMaterial: .init(data: data), salt: salt, info: "agreement".utf8Data, outputByteCount: 32)
            .withUnsafeBytes { Data($0) })!
    }
    
    public var peer: Peer {
        Peer(signingPublicKey: signingPrivateKey.schnorrPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
    
    public var ecdsaPeer: Peer {
        Peer(signingPublicKey: signingPrivateKey.ecdsaPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
}

extension Identity {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let data = CBOR.data(self.data)
        let salt = CBOR.data(self.salt)
        return CBOR.array([type, data, salt])
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.identity.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 3,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(data) = elements[1],
            case let CBOR.data(salt) = elements[2]
        else {
            throw CBORError.invalidFormat
        }
        self = Identity(data, salt: salt)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.identity.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension Identity {
    public var ur: UR {
        return try! UR(type: URType.identity.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.identity.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
}
