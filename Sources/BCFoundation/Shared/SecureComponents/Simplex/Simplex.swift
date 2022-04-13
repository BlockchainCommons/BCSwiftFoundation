import Foundation
import URKit
import WolfBase

public typealias SCID = UUID

// MARK: - Simplex

public struct Simplex {
    public let subject: Subject
    public let assertions: [Assertion]
    public let digest: Digest

    public init(subject: Subject, assertions: [Assertion] = []) {
        self.subject = subject
        let sortedAssertions = assertions.sorted()
        self.assertions = sortedAssertions
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        self.digest = Digest(Data(digests.map { $0.rawValue }.joined()))
    }
}

extension Simplex {
    public init(plaintext: CBOREncodable, assertions: [Assertion] = []) {
        self.init(subject: Subject(plaintext: plaintext), assertions: assertions)
    }
    
    public func plaintext<T>(_ type: T.Type) throws -> T where T: CBORDecodable {
        guard let cbor = self.plaintext else {
            throw CBORError.invalidFormat
        }
        return try T.cborDecode(cbor)
    }
    
    public var plaintext: CBOR? {
        subject.plaintext
    }
}

extension Simplex {
    public init(plaintext: CBOREncodable, assertions: [Assertion] = [], key: SymmetricKey, aad: Data? = nil, nonce: EncryptedMessage.Nonce? = nil) {
        let subject = Subject(plaintext: plaintext, key: key, aad: aad, nonce: nonce)
        self.init(subject: subject, assertions: assertions)
    }
    
    public func plaintext<T>(_ type: T.Type, with key: SymmetricKey) throws -> T where T: CBORDecodable {
        let cbor = try self.plaintext(with: key)
        return try T.cborDecode(cbor)
    }
    
    public func plaintext(with key: SymmetricKey) throws -> CBOR {
        try subject.plaintext(with: key)
    }
}

extension Simplex: Equatable {
    public static func ==(lhs: Simplex, rhs: Simplex) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Simplex: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(plaintext: value)
    }
}

extension Simplex {
    public init(subject: Subject, signatures: [Signature]) {
        let assertions = signatures.map {
            Predicate.authenticatedBy(signature: $0)
        }
        self.init(subject: subject, assertions: assertions)
    }
}

extension Simplex {
    public init(plaintext: CBOREncodable, schnorrSigners: [PrivateKeyBase], tag: Data = Data()) {
        let subject = Subject(plaintext: plaintext)
        let signatures = schnorrSigners.map {
            $0.signingPrivateKey.schnorrSign(subject.digest, tag: tag)
        }
        self.init(subject: subject, signatures: signatures)
    }
    
    public init(plaintext: CBOREncodable, schnorrSigner: PrivateKeyBase, tag: Data = Data()) {
        self.init(plaintext: plaintext, schnorrSigners: [schnorrSigner], tag: tag)
    }
}

extension Simplex {
    public init(plaintext: CBOREncodable, ecdsaSigners: [PrivateKeyBase]) {
        let subject = Subject(plaintext: plaintext)
        let signatures = ecdsaSigners.map {
            $0.signingPrivateKey.ecdsaSign(plaintext.cbor.cborEncode)
        }
        self.init(subject: subject, signatures: signatures)
    }
    
    public init(plaintext: CBOREncodable, ecdsaSigner: PrivateKeyBase) {
        self.init(plaintext: plaintext, ecdsaSigners: [ecdsaSigner])
    }
}

extension Simplex {
    public var signatures: [Signature] {
        get throws {
            try assertions
                .filter { $0.predicate == Predicate.authenticatedBy }
                .map { try $0.object.plaintext(Signature.self) }
        }
    }
    
    public func isValidSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        return key.isValidSignature(signature, for: subject.digest)
    }
    
    public func isValidSignature(_ signature: Signature, publicKeys: PublicKeyBase) -> Bool {
        isValidSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    public func hasValidSignature(key: SigningPublicKey) throws -> Bool {
        try signatures.contains { isValidSignature($0, key: key) }
    }
    
    public func hasValidSignature(from publicKeys: PublicKeyBase) throws -> Bool {
        try hasValidSignature(key: publicKeys.signingPublicKey)
    }
    
    public func hasValidSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Bool {
        let threshold = threshold ?? keys.count
        var count = 0
        for key in keys {
            if try hasValidSignature(key: key) {
                count += 1
                if count >= threshold {
                    return true
                }
            }
        }
        return false
    }
    
    public func hasValidSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Bool {
        try hasValidSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }
}

extension Simplex {
    public var untaggedCBOR: CBOR {
        var array = [subject.untaggedCBOR]
        if !assertions.isEmpty {
            array.append(CBOR.array(assertions.map { $0.untaggedCBOR }))
        }
        return CBOR.array(array)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.simplex.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            (1...2).contains(elements.count)
        else {
            throw CBORError.invalidFormat
        }
        
        let subject = try Subject(untaggedCBOR: elements[0])
        
        let assertions: [Assertion]
        if elements.count == 2 {
            guard
                case let CBOR.array(assertionElements) = elements[1],
                !assertionElements.isEmpty
            else {
                throw CBORError.invalidFormat
            }
            assertions = try assertionElements.map {
                try Assertion(untaggedCBOR: $0)
            }
        } else {
            assertions = []
        }
        
        self.init(subject: subject, assertions: assertions)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.simplex.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Simplex {
    public var ur: UR {
        return try! UR(type: URType.simplex.type, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.simplex.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
