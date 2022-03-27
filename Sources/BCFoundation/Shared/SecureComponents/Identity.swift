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
        self.data = provider.identityData
        self.salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))
    }
    
    public var privateSigningKey: PrivateSigningKey {
        return .init(rawValue: HKDF<SHA512>.deriveKey(inputKeyMaterial: .init(data: data), salt: salt, info: "signing".utf8Data, outputByteCount: 32)
            .withUnsafeBytes { Data($0) })!
    }
    
    public var publicSigningKey: PublicSigningKey {
        privateSigningKey.publicKey
    }
    
    public var privateAgreementKey: PrivateAgreementKey {
        return .init(rawValue: HKDF<SHA512>.deriveKey(inputKeyMaterial: .init(data: data), salt: salt, info: "agreement".utf8Data, outputByteCount: 32)
            .withUnsafeBytes { Data($0) })!
    }
    
    public var publicAgreementKey: PublicAgreementKey {
        .init(privateAgreementKey)
    }
}
