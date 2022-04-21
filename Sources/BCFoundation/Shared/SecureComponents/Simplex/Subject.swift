import Foundation
import URKit

public enum Subject {
    case leaf(CBOR, Digest)
    case encrypted(EncryptedMessage, Digest)
}

extension Subject {
    public var digest: Digest {
        switch self {
        case .leaf(_, let digest):
            return digest
        case .encrypted(_, let digest):
            return digest
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
        self = .leaf(cbor, Digest(encodedCBOR))
    }
    
    init(predicate: Predicate) {
        self.init(plaintext: CBOR.tagged(.predicate, CBOR.unsignedInt(predicate.rawValue)))
    }
    
    var plaintext: CBOR? {
        guard case let .leaf(plaintext, _) = self else {
            return nil
        }
        return plaintext
    }
}

extension Subject {
    var untaggedCBOR: CBOR {
        switch self {
        case .leaf(let plaintext, _):
            return [1.cbor, plaintext]
        case .encrypted(let message, let digest):
            return [2.cbor, message.taggedCBOR, digest.taggedCBOR]
//        case .reference(let identifier):
//            return [3.cbor, identifier.untaggedCBOR]
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
            self = .leaf(elements[1], Digest(elements[1]))
        case 2:
            guard elements.count == 3 else {
                throw CBORError.invalidFormat
            }
            self = try .encrypted(EncryptedMessage(taggedCBOR: elements[1]), Digest(taggedCBOR: elements[2]))
        default:
            throw CBORError.invalidFormat
        }
    }
}

extension Subject {
    public func encrypt(with key: SymmetricKey, aad: Data? = nil, nonce: Nonce? = nil) throws -> Subject {
        guard case let .leaf(cbor, digest) = self else {
            throw SimplexError.invalidOperation
        }
        
        let encodedCBOR = cbor.cborEncode
        let encryptedMessage = key.encrypt(plaintext: encodedCBOR, aad: aad, nonce: nonce)
        let result = Subject.encrypted(encryptedMessage, Digest(encodedCBOR))
        assert(digest == result.digest)
        return result
    }
    
    public func decrypt(with key: SymmetricKey) throws -> Subject {
        guard
            case let .encrypted(encryptedMessage, digest) = self
        else {
            throw SimplexError.invalidOperation
        }
        
        guard
            let data = key.decrypt(message: encryptedMessage)
        else {
            throw SimplexError.invalidKey
        }
        
        guard Digest.validate(data, digest: digest) else {
            throw SimplexError.invalidDigest
        }
        
        let cbor = try CBOR(data)
        return .leaf(cbor, digest)
    }
}
