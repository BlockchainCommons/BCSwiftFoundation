import Foundation
import URKit
import WolfBase

public typealias SCID = UUID

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
            Assertion.authenticated(signature: $0)
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
                .filter { $0.predicate == Assertion.authenticatedBy }
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

public enum Subject {
    case plaintext(CBOR, Digest)
    case encrypted(EncryptedMessage, Digest)
    case reference(Reference)
}

extension Subject {
    public var digest: Digest {
        switch self {
        case .plaintext(_, let digest):
            return digest
        case .encrypted(_, let digest):
            return digest
        case .reference(let identifier):
            return identifier.digest
        }
    }
}

extension Subject: Equatable {
    public static func ==(lhs: Subject, rhs: Subject) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Subject {
    init(plaintext: CBOREncodable) {
        let cbor = plaintext.cbor
        let encodedCBOR = cbor.cborEncode
        self = .plaintext(cbor, Digest(encodedCBOR))
    }
    
    var plaintext: CBOR? {
        guard case let .plaintext(plaintext, _) = self else {
            return nil
        }
        return plaintext
    }
}

extension Subject {
    var untaggedCBOR: CBOR {
        switch self {
        case .plaintext(let plaintext, _):
            return [1.cbor, plaintext]
        case .encrypted(let message, let digest):
            return [2.cbor, message.taggedCBOR, digest.taggedCBOR]
        case .reference(let identifier):
            return [3.cbor, identifier.untaggedCBOR]
        }
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count >= 2,
            case let CBOR.unsignedInt(type) = elements[0]
        else {
            throw CBORError.invalidFormat
        }
        
        switch type {
        case 1:
            guard elements.count == 2 else {
                throw CBORError.invalidFormat
            }
            self = .plaintext(elements[1], Digest(elements[1]))
        case 2:
            guard elements.count == 3 else {
                throw CBORError.invalidFormat
            }
            self = try .encrypted(EncryptedMessage(taggedCBOR: elements[1]), Digest(taggedCBOR: elements[2]))
        case 3:
            guard elements.count == 2 else {
                throw CBORError.invalidFormat
            }
            self = try .reference(Reference(untaggedCBOR: elements[1]))
        default:
            throw CBORError.invalidFormat
        }
    }
}

public enum Reference {
    case digest(Digest)
    case scid(SCID, Digest)
    
    public init(digest: Digest) {
        self = .digest(digest)
    }
    
    public init(uuid: SCID) {
        self = .scid(uuid, Digest(uuid.serialized))
    }
    
    public var digest: Digest {
        switch self {
        case .digest(let digest):
            return digest
        case .scid(_, let digest):
            return digest
        }
    }
}

extension Reference: Equatable {
    public static func ==(lhs: Reference, rhs: Reference) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Reference {
    var untaggedCBOR: CBOR {
        switch self {
        case .digest(let digest):
            return digest.taggedCBOR
        case .scid(let scid, _):
            return scid.taggedCBOR
        }
    }
    
    init(untaggedCBOR: CBOR) throws {
        todo()
    }
}

public enum Assertion {
    case declare(predicate: Simplex, object: Simplex, digest: Digest)
    case amend(assertion: Reference, object: Simplex, digest: Digest)
    case revoke(assertion: Reference, digest: Digest)
    
    public init(predicate: Simplex, object: Simplex) {
        let digest = Digest("declare".utf8Data + predicate.digest.rawValue + object.digest.rawValue)
        self = .declare(predicate: predicate, object: object, digest: digest)
    }
    
    public init(amend assertion: Reference, object: Simplex) {
        let digest = Digest("amend".utf8Data + assertion.digest.rawValue + object.digest.rawValue)
        self = .amend(assertion: assertion, object: object, digest: digest)
    }
    
    public init(revoke assertion: Reference) {
        let digest = Digest("revoke".utf8Data + assertion.digest.rawValue)
        self = .revoke(assertion: assertion, digest: digest)
    }
}

extension Assertion {
    public var digest: Digest {
        switch self {
        case .declare(_, _, let digest):
            return digest
        case .amend(_, _, let digest):
            return digest
        case .revoke(_, let digest):
            return digest
        }
    }
}

extension Assertion: Equatable {
    public static func ==(lhs: Assertion, rhs: Assertion) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Assertion: Comparable {
    public static func <(lhs: Assertion, rhs: Assertion) -> Bool {
        lhs.digest < rhs.digest
    }
}

extension Assertion {
    var untaggedCBOR: CBOR {
        switch self {
        case .declare(let predicate, let object, _):
            return [1.cbor, predicate.untaggedCBOR, object.untaggedCBOR]
        case .amend(let assertion, let object, _):
            return [2.cbor, assertion.untaggedCBOR, object.untaggedCBOR]
        case .revoke(let assertion, _):
            return [3.cbor, assertion.untaggedCBOR]
        }
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count >= 2,
            case let CBOR.unsignedInt(type) = elements[0]
        else {
            throw CBORError.invalidFormat
        }
        
        switch type {
        case 1:
            guard elements.count == 3 else {
                throw CBORError.invalidFormat
            }
            let predicate = try Simplex(untaggedCBOR: elements[1])
            let object = try Simplex(untaggedCBOR: elements[2])
            self.init(predicate: predicate, object: object)
        case 2:
            guard elements.count == 3 else {
                throw CBORError.invalidFormat
            }
            let assertion = try Reference(untaggedCBOR: elements[1])
            let object = try Simplex(untaggedCBOR: elements[2])
            self.init(amend: assertion, object: object)
        case 3:
            guard elements.count == 2 else {
                throw CBORError.invalidFormat
            }
            let assertion = try Reference(untaggedCBOR: elements[1])
            self.init(revoke: assertion)
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public var predicate: Simplex {
        switch self {
        case .declare(let predicate, _, _):
            return predicate
        default:
            todo()
        }
    }
    
    public var object: Simplex {
        switch self {
        case .declare(_, let object, _):
            return object
        default:
            todo()
        }
    }
    
    public static let authenticatedBy = Simplex(1)
    
    public static func authenticated(signature: Signature) -> Assertion {
        Assertion(predicate: authenticatedBy, object: Simplex(plaintext: signature))
    }
}
