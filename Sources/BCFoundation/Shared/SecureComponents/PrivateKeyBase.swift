import Foundation
import CryptoKit
import WolfBase
import BLAKE3

/// Types can conform to `PrivateKeysDataProvider` to indicate that they will provide
/// unique data from which keys for signing and encryption can be derived.
///
/// Conforming types include `Data`, `Seed`, `HDKey`, and `Password`.
public protocol PrivateKeysDataProvider {
    var privateKeysData: Data { get }
}

extension Data: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        self
    }
}

extension Seed: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        data
    }
}

extension HDKey: PrivateKeysDataProvider {
    public var privateKeysData: Data {
        keyData
    }
}

/// Holds unique data from which keys for signing and encryption can be derived and
/// a field of random salt used in the key derivation process.
///
/// Derivation is performed used BLAKE3.
///
/// https://datatracker.ietf.org/doc/html/rfc5869
public struct PrivateKeyBase {
    public let data: Data
    
    public init(_ provider: PrivateKeysDataProvider) {
        self.data = provider.privateKeysData
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))
    }
    
    public var signingPrivateKey: SigningPrivateKey {
        .init(BLAKE3.deriveKey(fromContentsOf: data, withContext: "signing").data)!
    }
    
    public var agreementPrivateKey: AgreementPrivateKey {
        .init(BLAKE3.deriveKey(fromContentsOf: data, withContext: "agreement").data)!
    }
    
    public var publicKeys: PublicKeyBase {
        PublicKeyBase(signingPublicKey: signingPrivateKey.schnorrPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
    
    public var ecdsaPublicKeys: PublicKeyBase {
        PublicKeyBase(signingPublicKey: signingPrivateKey.ecdsaPublicKey, agreementPublicKey: agreementPrivateKey.publicKey)
    }
}

extension PrivateKeyBase {
    public var untaggedCBOR: CBOR {
        data.cbor
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.privateKeyBase.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.data(data) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        self.init(data)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.privateKeyBase.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension PrivateKeyBase {
    public var ur: UR {
        return try! UR(type: URType.privateKeyBase.type, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.privateKeyBase.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
}

extension PrivateKeyBase: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
