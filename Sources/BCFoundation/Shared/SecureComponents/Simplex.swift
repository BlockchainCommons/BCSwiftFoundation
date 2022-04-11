import Foundation
import URKit
import WolfBase

public struct Simplex {
    public var subject: Subject
    public var assertions: [Assertion]
}

extension Simplex {
    public init(plaintext: CBOR) {
        self.subject = .plaintext(plaintext)
        self.assertions = []
    }
    
    public init(plaintext: CBOREncodable) {
        self.subject = .plaintext(plaintext.cbor)
        self.assertions = []
    }
    
    public func plaintext<T>(_ type: T.Type) throws -> T? where T: CBORDecodable {
        guard let cbor = self.plaintext else {
            return nil
        }
        return try T.cborDecode(cbor)
    }
    
    public var plaintext: CBOR? {
        subject.plaintext
    }
}

extension Simplex {
    var sortedAssertions: [Assertion] {
        assertions
            .map { (Digest($0.cbor.cborEncode), $0) }
            .sorted { $0.0 < $1.0 }
            .map { $0.1 }
    }
    
    public var cbor: CBOR {
        var array = [subject.cbor]
        if !assertions.isEmpty {
            array.append(CBOR.array(sortedAssertions.map { $0.cbor }))
        }
        return CBOR.array(array)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.simplex.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            (1...2).contains(elements.count)
        else {
            throw CBORError.invalidFormat
        }
        
        self.subject = try Subject(cbor: elements[0])
        
        let assertions: [Assertion]
        if elements.count == 2 {
            guard
                case let CBOR.array(assertionElements) = elements[1],
                !assertionElements.isEmpty
            else {
                throw CBORError.invalidFormat
            }
            assertions = try assertionElements.map {
                try Assertion(cbor: $0)
            }
        } else {
            assertions = []
        }
        
        self.assertions = assertions
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.simplex.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
}

extension Simplex {
    public var ur: UR {
        return try! UR(type: URType.simplex.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.simplex.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

public enum Subject {
    case plaintext(CBOR)
    case encrypted(EncryptedMessage, Digest)
    case reference(Identifier)
}

extension Subject {
    var plaintext: CBOR? {
        guard case let .plaintext(plaintext) = self else {
            return nil
        }
        return plaintext
    }
}

extension Subject {
    var cbor: CBOR {
        switch self {
        case .plaintext(let plaintext):
            return [1.cbor, plaintext]
        case .encrypted(let message, let digest):
            return [2.cbor, message.taggedCBOR, digest.taggedCBOR]
        case .reference(let identifier):
            return [3.cbor, identifier.cbor]
        }
    }
    
    init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
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
            self = .plaintext(elements[1])
        case 2:
            guard elements.count == 3 else {
                throw CBORError.invalidFormat
            }
            self = try .encrypted(EncryptedMessage(taggedCBOR: elements[1]), Digest(taggedCBOR: elements[2]))
        case 3:
            guard elements.count == 2 else {
                throw CBORError.invalidFormat
            }
            self = try .reference(Identifier(cbor: elements[1]))
        default:
            throw CBORError.invalidFormat
        }
    }
}

public enum Identifier {
    case digest(Digest)
    case uuid(UUID)
}

extension Identifier {
    var cbor: CBOR {
        switch self {
        case .digest(let digest):
            todo()
        case .uuid(let uuid):
            todo()
        }
    }
    
    init(cbor: CBOR) throws {
        todo()
    }
}

public enum Assertion {
    case declare(predicate: Simplex, object: Simplex)
    case amend(assertion: Identifier, object: Simplex)
    case revoke(assertion: Identifier)
}

extension Assertion {
    var cbor: CBOR {
        switch self {
        case .declare(let predicate, let object):
            todo()
        case .amend(let asserion, let object):
            todo()
        case .revoke(let assertion):
            todo()
        }
    }
    
    init(cbor: CBOR) throws {
        todo()
    }
}
