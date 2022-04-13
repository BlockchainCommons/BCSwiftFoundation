import Foundation
import URKit

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
        case .reference(let reference):
            return reference.digest
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
    
    init(plaintext: CBOREncodable, key: SymmetricKey, aad: Data? = nil, nonce: Nonce? = nil) {
        let encodedCBOR = plaintext.cbor.cborEncode
        let encryptedMessage = key.encrypt(plaintext: encodedCBOR, aad: aad, nonce: nonce)
        self = .encrypted(encryptedMessage, Digest(encodedCBOR))
    }
    
    func plaintext(with key: SymmetricKey) throws -> CBOR {
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
        return try CBOR(data)
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

extension Subject {
    public func encrypted(with key: SymmetricKey, aad: Data? = nil, nonce: Nonce? = nil) throws -> Subject {
        guard case let .plaintext(cbor, digest) = self else {
            throw SimplexError.invalidOperation
        }
        
        let result = Subject(plaintext: cbor, key: key, aad: aad, nonce: nonce)
        assert(digest == result.digest)
        return result
    }
    
    public func decrypted(with key: SymmetricKey) throws -> Subject {
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
        return .plaintext(cbor, digest)
    }
}
