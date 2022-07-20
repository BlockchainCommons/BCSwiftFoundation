import Foundation
import URKit
import WolfBase
import CryptoKit
import SSKR

public struct Envelope: DigestProvider {
    public let subject: Subject
    public let assertions: [Assertion]
    public let digest: Digest
}

extension Envelope {
    public init(subject: Subject, assertions: [Assertion] = []) {
        self.subject = subject
        let sortedAssertions = assertions.sorted()
        self.assertions = sortedAssertions
        var digests = [subject.digest]
        digests.append(contentsOf: sortedAssertions.map { $0.digest })
        self.digest = Digest(Data(digests.map { $0.data }.joined()))
    }
    
    public init(digest: Digest) {
        self.subject = .redacted(digest)
        self.assertions = []
        self.digest = digest
    }
}

extension Envelope {
    public var deepDigests: Set<Digest> {
        var result = subject.deepDigests.union([digest])
        for assertion in assertions {
            result.formUnion(assertion.deepDigests)
        }
        return result
    }
    
    public var shallowDigests: Set<Digest> {
        [digest, subject.digest]
    }
}

extension Envelope: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Envelope: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Envelope {
        try Envelope(taggedCBOR: cbor)
    }
}

extension Envelope {
    public init(_ plaintext: CBOREncodable) {
        self.init(subject: Subject(plaintext: plaintext))
    }
    
    public init(predicate: Predicate) {
        self.init(subject: Subject(predicate: predicate))
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
    
    public var envelope: Envelope? {
        subject.envelope
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
    
    public func enclose() -> Envelope {
        Envelope(subject: Subject(plaintext: self))
    }
    
    public func extract() throws -> Envelope {
        guard
            let envelope = envelope
        else {
            throw EnvelopeError.invalidFormat
        }
        return envelope
    }
}

extension Envelope: Equatable {
    public static func ==(lhs: Envelope, rhs: Envelope) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Envelope: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self.init(value)
    }
}

extension Envelope {
    public func assertions(predicate: CBOREncodable) -> [Assertion] {
        let predicate = Envelope(predicate)
        return assertions.filter { $0.predicate == predicate }
    }

    public func assertion(predicate: CBOREncodable) throws -> Assertion {
        let a = assertions(predicate: predicate)
        guard a.count == 1 else {
            throw EnvelopeError.invalidFormat
        }
        return a.first!
    }

    public func extract(predicate: CBOREncodable) throws -> Envelope {
        try assertion(predicate: predicate).object
    }
    
    public func extract<T>(predicate: CBOREncodable, _ type: T.Type) throws -> T where T: CBORDecodable {
        try extract(predicate: predicate).extract(type)
    }
}

extension Envelope {
    public func assertions(predicate: Predicate) -> [Assertion] {
        let p = Envelope(predicate: predicate)
        return assertions.filter { $0.predicate == p }
    }
    
    public func assertion(predicate: Predicate) throws -> Assertion {
        let a = assertions(predicate: predicate)
        guard a.count == 1 else {
            throw EnvelopeError.invalidFormat
        }
        return a.first!
    }
    
    public func extract(predicate: Predicate) throws -> Envelope {
        try assertion(predicate: predicate).object
    }
    
    public func extract<T>(predicate: Predicate, _ type: T.Type) throws -> T where T: CBORDecodable {
        try extract(predicate: predicate).extract(type)
    }
}

extension Envelope {
    public func add(_ assertion: Assertion) -> Envelope {
        if !assertions.contains(assertion) {
            return Envelope(subject: self.subject, assertions: assertions.appending(assertion))
        } else {
            return self
        }
    }
    
    public func add(_ predicate: CBOREncodable, _ object: CBOREncodable) -> Envelope {
        let p = predicate as? Envelope ?? Envelope(predicate)
        let o = object as? Envelope ?? Envelope(object)
        return add(Assertion(p, o))
    }

    public func add(_ predicate: Predicate, _ object: CBOREncodable) -> Envelope {
        return add(Envelope(predicate: predicate), object)
    }
}

extension Envelope {
    public func sign(with privateKeys: PrivateKeyBase, note: String? = nil, tag: Data? = nil) -> Envelope {
        let signature = privateKeys.signingPrivateKey.schnorrSign(subject.digest, tag: tag)
        return add(.verifiedBy(signature: signature, note: note))
    }
    
    public func sign(with privateKeys: [PrivateKeyBase], tag: Data? = nil) -> Envelope {
        var result = self
        for keys in privateKeys {
            result = result.sign(with: keys)
        }
        return result
    }
    
    public func addRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey) -> Envelope {
        add(.hasRecipient(recipient, contentKey: contentKey))
    }
    
    public func addSSKRShare(_ share: SSKRShare) -> Envelope {
        add(.sskrShare(share))
    }
    
    public func split(groupThreshold: Int, groups: [(Int, Int)], contentKey: SymmetricKey, randomGenerator: ((Int) -> Data)? = nil) -> [[Envelope]] {
        let shares = try! SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: contentKey, randomGenerator: randomGenerator)
        return shares.map { groupShares in
            groupShares.map { share in
                self.addSSKRShare(share)
            }
        }
    }
    
    public static func shares(in containers: [Envelope]) throws -> [UInt16: [SSKRShare]] {
        var result: [UInt16: [SSKRShare]] = [:]
        for container in containers {
            try container.assertions(predicate: .sskrShare)
                .forEach {
                    let share = try $0.object.extract(SSKRShare.self)
                    let identifier = share.identifier
                    if result[identifier] == nil {
                        result[identifier] = []
                    }
                    result[identifier]!.append(share)
                }
        }
        return result
    }

    public init(shares containers: [Envelope]) throws {
        guard !containers.isEmpty else {
            throw EnvelopeError.invalidShares
        }
        for shares in try Self.shares(in: containers).values {
            guard let contentKey = try? SymmetricKey(SSKRCombine(shares: shares)) else {
                continue
            }
            self = try containers.first!.decrypt(with: contentKey)
            return
        }
        throw EnvelopeError.invalidShares
    }
}

extension Envelope {
    public var signatures: [Signature] {
        get throws {
            try assertions(predicate: .verifiedBy)
                .map { try $0.object.extract(Signature.self) }
        }
    }
    
    public func isValidSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        return key.isValidSignature(signature, for: subject.digest)
    }
    
    @discardableResult
    public func validateSignature(_ signature: Signature, key: SigningPublicKey) throws -> Envelope {
        guard isValidSignature(signature, key: key) else {
            throw EnvelopeError.invalidSignature
        }
        return self
    }
    
    public func isValidSignature(_ signature: Signature, publicKeys: PublicKeyBase) -> Bool {
        isValidSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    @discardableResult
    public func validateSignature(_ signature: Signature, publicKeys: PublicKeyBase) throws -> Envelope {
        try validateSignature(signature, key: publicKeys.signingPublicKey)
    }
    
    public func hasValidSignature(key: SigningPublicKey) throws -> Bool {
        let sigs = try signatures
        return sigs.contains { isValidSignature($0, key: key) }
    }
    
    @discardableResult
    public func validateSignature(key: SigningPublicKey) throws -> Envelope {
        guard try hasValidSignature(key: key) else {
            throw EnvelopeError.invalidSignature
        }
        return self
    }
    
    public func hasValidSignature(from publicKeys: PublicKeyBase) throws -> Bool {
        try hasValidSignature(key: publicKeys.signingPublicKey)
    }
    
    @discardableResult
    public func validateSignature(from publicKeys: PublicKeyBase) throws -> Envelope {
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

    @discardableResult
    public func validateSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) throws -> Envelope {
        guard try hasValidSignatures(with: keys, threshold: threshold) else {
            throw EnvelopeError.invalidSignature
        }
        return self
    }

    public func hasValidSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Bool {
        try hasValidSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }

    @discardableResult
    public func validateSignatures(from publicKeysArray: [PublicKeyBase], threshold: Int? = nil) throws -> Envelope {
        try validateSignatures(with: publicKeysArray.map { $0.signingPublicKey }, threshold: threshold)
    }
}

extension Envelope {
    public func encrypt(with key: SymmetricKey, nonce: Nonce? = nil) throws -> Envelope {
        let subject = try self.subject.encrypt(with: key, nonce: nonce)
        let result = Envelope(subject: subject, assertions: assertions)
        assert(digest == result.digest)
        return result
    }
    
    public func decrypt(with key: SymmetricKey) throws -> Envelope {
        let subject = try self.subject.decrypt(with: key)
        let result = Envelope(subject: subject, assertions: assertions)
        assert(digest == result.digest)
        return result
    }
}

extension Envelope {
    public var recipients: [SealedMessage] {
        get throws {
            try assertions(predicate: .hasRecipient)
                .map { try $0.object.extract(SealedMessage.self) }
        }
    }
    
    public func decrypt(to recipient: PrivateKeyBase) throws -> Envelope {
        guard
            let contentKeyData = try SealedMessage.firstPlaintext(in: recipients, for: recipient)
        else {
            throw EnvelopeError.invalidRecipient
        }
        
        let cbor = try CBOR(contentKeyData)
        let contentKey = try SymmetricKey(taggedCBOR: cbor)
        return try decrypt(with: contentKey)
    }
}

extension Envelope {
    public func redact() -> Envelope {
        let result = Envelope(digest: digest)
        assert(result.digest == digest)
        return result
    }
    
    public func redact(items: Set<Digest>) -> Envelope {
        if items.contains(digest) {
            return redact()
        }
        let subject = self.subject.redact(items: items)
        let assertions = self.assertions.map {
            $0.redact(items: items)
        }
        let result = Envelope(subject: subject, assertions: assertions)
        assert(result.digest == digest)
        return result
    }
    
    public func redact(revealing items: Set<Digest>) -> Envelope {
        if !items.contains(digest) {
            return redact()
        }
        let subject = self.subject.redact(revealing: items)
        let assertions = self.assertions.map {
            $0.redact(revealing: items)
        }
        let result = Envelope(subject: subject, assertions: assertions)
        assert(result.digest == digest)
        return result
    }
}

extension Envelope {
    public func revoke(_ digest: Digest) -> Envelope {
        var assertions = self.assertions
        if let index = assertions.firstIndex(where: { $0.digest == digest }) {
            assertions.remove(at: index)
        }
        return Envelope(subject: subject, assertions: assertions)
    }
}

extension Envelope {
    public var untaggedCBOR: CBOR {
        if assertions.isEmpty {
            return subject.cbor
        } else {
            var array = [subject.cbor]
            array.append(contentsOf: assertions.map { $0.untaggedCBOR })
            return CBOR.array(array)
        }
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.envelope.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        if case let CBOR.array(elements) = untaggedCBOR {
            guard elements.count >= 2 else {
                throw CBORError.invalidFormat
            }
            let subject = try Subject(cbor: elements[0])
            let assertions = try elements.dropFirst().map { try Assertion(untaggedCBOR: $0 ) }
            self.init(subject: subject, assertions: assertions)
        } else {
            try self.init(subject: Subject(cbor: untaggedCBOR), assertions: [])
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.envelope.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Envelope {
    public var ur: UR {
        return try! UR(type: URType.envelope.type, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.envelope.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
