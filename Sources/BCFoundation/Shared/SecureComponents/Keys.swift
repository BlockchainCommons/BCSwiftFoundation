import Foundation
import CryptoKit

/// Implements EdDSA signature over Curve25519.
///
/// https://datatracker.ietf.org/doc/html/rfc8032
///
/// Note: “CryptoKit implementation of the algorithm employs randomization to generate a different signature on every call, even for the same data and key, to guard against side-channel attacks.”
public struct PrivateSigningKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data

    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }

    public init() {
        self.rawValue = Curve25519.Signing.PrivateKey().rawRepresentation
    }
    
    public func sign(data: DataProvider) -> Signature {
        return try! Signature(rawValue: cryptoKitForm.signature(for: data.providedData))!
    }
    
    public var description: String {
        "PrivateSigningKey(\(rawValue))"
    }
    
    var cryptoKitForm: Curve25519.Signing.PrivateKey {
        try! .init(rawRepresentation: rawValue)
    }
}

extension PrivateSigningKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.privateSigningKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PrivateSigningKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.privateSigningKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

public struct PublicSigningKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public init(_ privateKey: PrivateSigningKey) {
        self.rawValue = privateKey.cryptoKitForm.publicKey.rawRepresentation
    }
    
    public var description: String {
        "PublicSigningKey(\(rawValue.hex))"
    }
    
    var cryptoKitForm: Curve25519.Signing.PublicKey {
        try! .init(rawRepresentation: rawValue)
    }
    
    public func isValidSignature(_ signature: Signature, for data: DataProvider) -> Bool {
        cryptoKitForm.isValidSignature(signature.rawValue, for: data.providedData)
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

public struct PrivateAgreementKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        self.rawValue = rawValue
    }
    
    public init() {
        self.rawValue = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
    }
    
    public var description: String {
        "PrivateAgreementKey\(rawValue)"
    }

    public var cryptoKitForm: Curve25519.KeyAgreement.PrivateKey {
        try! .init(rawRepresentation: rawValue)
    }
}

extension PrivateAgreementKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.privateAgreementKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PrivateAgreementKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.privateAgreementKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

public struct PublicAgreementKey: RawRepresentable, CustomStringConvertible, Hashable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        self.rawValue = rawValue
    }
    
    public init(_ privateKey: PrivateAgreementKey) {
        self.rawValue = privateKey.cryptoKitForm.publicKey.rawRepresentation
    }
    
    public var description: String {
        "PublicAgreementKey\(rawValue.hex)"
    }
    
    public var cryptoKitForm: Curve25519.KeyAgreement.PublicKey {
        try! .init(rawRepresentation: rawValue)
    }
}

extension PublicAgreementKey {
    public var cbor: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.publicAgreementKey, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = cbor,
            let key = PublicAgreementKey(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.publicAgreementKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
