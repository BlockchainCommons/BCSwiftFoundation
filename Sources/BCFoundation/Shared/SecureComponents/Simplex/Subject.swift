import Foundation

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
    
    init(plaintext: CBOREncodable, key: SymmetricKey, aad: Data? = nil, nonce: EncryptedMessage.Nonce? = nil) {
        let encodedCBOR = plaintext.cbor.cborEncode
        let encryptedMessage = key.encrypt(plaintext: encodedCBOR, aad: aad, nonce: nonce)
        self = .encrypted(encryptedMessage, Digest(encodedCBOR))
    }
    
    func plaintext(with key: SymmetricKey) throws -> CBOR {
        guard
            case let .encrypted(encryptedMessage, digest) = self,
            let data = key.decrypt(message: encryptedMessage)
        else {
            throw CBORError.invalidFormat
        }
        try Digest.tryValidate(data, digest: digest)
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
