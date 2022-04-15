import Foundation
import URKit
import WolfBase
import CryptoKit

public struct Simplex {
    public let subject: Subject
    public let assertions: [Assertion]
    public let digest: Digest
}

extension Simplex {
    public init(subject: Subject, assertions: [Assertion] = []) {
        self.subject = subject
        let sortedAssertions = assertions.sorted()
        self.assertions = sortedAssertions
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        self.digest = Digest(Data(digests.map { $0.rawValue }.joined()))
    }
}

extension Simplex: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Simplex: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Simplex {
        try Simplex(taggedCBOR: cbor)
    }
}

extension Simplex {
    public init(enclose plaintext: CBOREncodable, assertions: [Assertion] = []) {
        self.init(subject: Subject(plaintext: plaintext), assertions: assertions)
    }
    
    public init(predicate: Predicate, assertions: [Assertion] = []) {
        self.init(subject: Subject(predicate: predicate), assertions: assertions)
    }
    
    public func extract<T>(_ type: T.Type) throws -> T where T: CBORDecodable {
        guard let cbor = self.plaintext else {
            throw CBORError.invalidFormat
        }
        return try T.cborDecode(cbor)
    }
    
    public var plaintext: CBOR? {
        subject.plaintext
    }
    
    public var predicate: Predicate? {
        guard
            let plaintext = plaintext,
            case let CBOR.tagged(.predicate, value) = plaintext,
            case let CBOR.unsignedInt(rawValue) = value,
            let predicate = Predicate(rawValue: rawValue)
        else {
            return nil
        }
        
        return predicate
    }
    
    public func enclose() -> Simplex {
        Simplex(subject: Subject(plaintext: self))
    }
    
    public func extract() throws -> Simplex {
        guard
            let plaintext = plaintext
        else {
            throw SimplexError.invalidFormat
        }
        return try Simplex(taggedCBOR: plaintext)
    }
}

extension Simplex: Equatable {
    public static func ==(lhs: Simplex, rhs: Simplex) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Simplex: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(enclose: value)
    }
}

extension Simplex {
    public func addingAssertion(_ assertion: Assertion) -> Simplex {
        Simplex(subject: self.subject, assertions: assertions.appending(assertion))
    }
    
    public func sign(with privateKeys: PrivateKeyBase, tag: Data = Data()) -> Simplex {
        let signature = privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag)
        let assertion = Assertion.authenticatedBy(signature: signature)
        return addingAssertion(assertion)
    }
    
    public func sign(with privateKeys: [PrivateKeyBase], tag: Data = Data()) -> Simplex {
        var result = self
        for keys in privateKeys {
            result = result.sign(with: keys)
        }
        return result
    }
}

extension Simplex {
    public var signatures: [Signature] {
        get throws {
            try assertions
                .filter { $0.predicate == Predicate.authenticatedBy }
                .map { try $0.object.extract(Signature.self) }
        }
    }
    
    public func isValidSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        return key.isValidSignature(signature, for: subject.digest)
    }
    
    public func validateSignature(_ signature: Signature, key: SigningPublicKey) throws -> Simplex {
        guard isValidSignature(signature, key: key) else {
            throw SimplexError.invalidSignature
        }
        return self
    }
    
    public func isValidSignature(_ signature: Signature, publicKeys: PublicKeyBase) -> Bool {
        isValidSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    public func validateSignature(_ signature: Signature, publicKeys: PublicKeyBase) throws -> Simplex {
        try validateSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    public func hasValidSignature(key: SigningPublicKey) throws -> Bool {
        let sigs = try signatures
        return sigs.contains { isValidSignature($0, key: key) }
    }
    
    public func validateSignature(key: SigningPublicKey) throws -> Simplex {
        guard try hasValidSignature(key: key) else {
            throw SimplexError.invalidSignature
        }
        return self
    }
    
    public func hasValidSignature(from publicKeys: PublicKeyBase) throws -> Bool {
        try hasValidSignature(key: publicKeys.signingPublicKey)
    }
    
    public func validateSignature(from publicKeys: PublicKeyBase) throws -> Simplex {
        try validateSignature(key: publicKeys.signingPublicKey)
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

    public func validateSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Simplex {
        guard try hasValidSignatures(with: keys, threshold: threshold) else {
            throw SimplexError.invalidSignature
        }
        return self
    }

    public func hasValidSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Bool {
        try hasValidSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }

    public func validateSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Simplex {
        try validateSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }
}

extension Simplex {
    public func encrypt(with key: SymmetricKey, aad: Data? = nil, nonce: Nonce? = nil) throws -> Simplex {
        let subject = try self.subject.encrypt(with: key, aad: aad, nonce: nonce)
        let result = Simplex(subject: subject, assertions: assertions)
        assert(digest == result.digest)
        return result
    }
    
    public func decrypt(with key: SymmetricKey) throws -> Simplex {
        let subject = try self.subject.decrypt(with: key)
        let result = Simplex(subject: subject, assertions: assertions)
        assert(digest == result.digest)
        return result
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
