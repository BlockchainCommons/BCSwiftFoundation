import Foundation
import WolfBase
import SSKR

public enum Assertion {
    case declare(predicate: Simplex, object: Simplex, digest: Digest)
    case amend(assertion: Reference, object: Simplex, digest: Digest)
    case revoke(assertion: Reference, digest: Digest)
}

extension Assertion {
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
    public static func authenticatedBy(signature: Signature) -> Assertion {
        Assertion(predicate: Simplex(predicate: .authenticatedBy), object: Simplex(enclose: signature))
    }
    
    public static func hasRecipient(_ recipient: PublicKeyBase, contentKey: SymmetricKey) -> Assertion {
        let sealedMessage = SealedMessage(plaintext: contentKey.taggedCBOR, recipient: recipient)
        return Assertion(predicate: Simplex(predicate: .hasRecipient), object: Simplex(enclose: sealedMessage))
    }
    
    public static func sskrShare(_ share: SSKRShare) -> Assertion {
        Assertion(predicate: Simplex(predicate: .sskrShare), object: Simplex(enclose: share))
    }
    
    public static func isA(_ object: Simplex) -> Assertion {
        Assertion(predicate: Simplex(predicate: .isA), object: object)
    }
    
    public static func id(_ id: SCID) -> Assertion {
        Assertion(predicate: Simplex(predicate: .id), object: Simplex(enclose: id))
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
    
    public var predicate: Predicate? {
        switch self {
        case .declare(let predicate, _, _):
            return predicate.predicate
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
}
