import Foundation
import WolfBase
import SSKR
import URKit

public struct Assertion: DigestProvider {
    public let predicate: Simplex
    public let object: Simplex
    public let digest: Digest
}

extension Assertion {
    public init(_ predicate: Simplex, _ object: Simplex) {
        self.predicate = predicate
        self.object = object
        self.digest = Digest(predicate.digest.rawValue + object.digest.rawValue)
    }
}

extension Assertion {
    public var deepDigests: Set<Digest> {
        predicate.deepDigests.union(object.deepDigests).union([digest])
    }
    
    public var shallowDigests: Set<Digest> {
        [
            digest,
            predicate.digest, predicate.subject.digest,
            object.digest, object.subject.digest
        ]
    }
}

extension Assertion {
    public func assertions(predicate: CBOREncodable) -> [Assertion] {
        object.assertions(predicate: predicate)
    }
    
    public func assertion(predicate: CBOREncodable) throws -> Assertion {
        try object.assertion(predicate: predicate)
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
    public static func verifiedBy(signature: Signature, note: String? = nil) -> Assertion {
        var object = Simplex(signature)
        if let note = note {
            object = object.add(.note, note)
        }
        return Assertion(Simplex(predicate: .verifiedBy), object)
    }
    
    public static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey) -> Assertion {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR, recipient: recipient)
        return Assertion(Simplex(predicate: .hasRecipient), Simplex(sealedMessage))
    }
    
    public static func sskrShare(_ share: SSKRShare) -> Assertion {
        Assertion(Simplex(predicate: .sskrShare), Simplex(share))
    }
    
    public static func isA(_ object: Simplex) -> Assertion {
        Assertion(Simplex(predicate: .isA), object)
    }
    
    public static func id(_ id: SCID) -> Assertion {
        Assertion(Simplex(predicate: .id), Simplex(id))
    }
}

extension Assertion {
    public func redact() -> Assertion {
        let result = Assertion(predicate.redact(), object.redact())
        assert(result.digest == digest)
        return result
    }
    
    public func redact(items: Set<Digest>) -> Assertion {
        if items.contains(digest) {
            return redact()
        }
        let result = Assertion(predicate.redact(items: items), object.redact(items: items))
        assert(result.digest == digest)
        return result
    }
    
    public func redact(revealing items: Set<Digest>) -> Assertion {
        if !items.contains(digest) {
            return redact()
        }
        let result = Assertion(predicate.redact(revealing: items), object.redact(revealing: items))
        assert(result.digest == digest)
        return result
    }
}

extension Assertion {
    var untaggedCBOR: CBOR {
        [predicate.taggedCBOR, object.taggedCBOR]
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2
        else {
            throw CBORError.invalidFormat
        }

        let predicate = try Simplex(taggedCBOR: elements[0])
        let object = try Simplex(taggedCBOR: elements[1])

        self.init(predicate, object)
    }
}
