import Foundation
import WolfBase
import SSKR

public enum Assertion {
    case declare(predicate: Simplex, object: Simplex, digest: Digest)
}

extension Assertion {
    public init(_ predicate: Simplex, _ object: Simplex) {
        let digest = Digest("declare".utf8Data + predicate.digest.rawValue + object.digest.rawValue)
        self = .declare(predicate: predicate, object: object, digest: digest)
    }
}

extension Assertion {
    public var digest: Digest {
        switch self {
        case .declare(_, _, let digest):
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
    public static func authenticatedBy(signature: Signature, note: String? = nil) -> Assertion {
        var object = Simplex(signature)
        if let note = note {
            object = object.add(.note, note)
        }
        return Assertion(Simplex(predicate: .authenticatedBy), object)
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
    var untaggedCBOR: CBOR {
        switch self {
        case .declare(let predicate, let object, _):
            return [1.cbor, predicate.untaggedCBOR, object.untaggedCBOR]
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
            self.init(predicate, object)
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public var predicate: Predicate? {
        predicateValue.predicate
    }
    
    public var predicateValue: Simplex {
        switch self {
        case .declare(let predicate, _, _):
            return predicate
        }
    }

    public var object: Simplex {
        switch self {
        case .declare(_, let object, _):
            return object
        }
    }
}
