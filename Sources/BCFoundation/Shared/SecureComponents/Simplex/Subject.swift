import Foundation
import URKit

public indirect enum Subject {
    case leaf(CBOR, Digest)
    case simplex(Simplex)
    case encrypted(EncryptedMessage, Digest)
}

extension Subject {
    public var digest: Digest {
        switch self {
        case .leaf(_, let digest):
            return digest
        case .simplex(let simplex):
            return simplex.digest
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
        if let simplex = plaintext as? Simplex {
            self = .simplex(simplex)
        } else {
            let cbor = plaintext.cbor
            let encodedCBOR = cbor.cborEncode
            self = .leaf(cbor, Digest(encodedCBOR))
        }
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
    
    var simplex: Simplex? {
        guard case let .simplex(simplex) = self else {
            return nil
        }
        return simplex
    }
}

extension Subject {
    var cbor: CBOR {
        switch self {
        case .simplex(let simplex):
            return simplex.taggedCBOR
        case .leaf(let plaintext, _):
            return CBOR.tagged(.plaintext, plaintext)
        case .encrypted(let message, _):
            return message.taggedCBOR
        }
    }
    
    init(cbor: CBOR) throws {
        if case CBOR.tagged(URType.simplex.tag, _) = cbor {
            self = try .simplex(Simplex(taggedCBOR: cbor))
        } else if case let CBOR.tagged(.plaintext, plaintext) = cbor {
            self = .leaf(plaintext, Digest(plaintext.cborEncode))
        } else if case CBOR.tagged(URType.message.tag, _) = cbor {
            let message = try EncryptedMessage(taggedCBOR: cbor)
            self = try .encrypted(message, message.digest)
        } else {
            throw SimplexError.invalidFormat
        }
    }
}

extension Subject {
    public func encrypt(with key: SymmetricKey, nonce: Nonce? = nil) throws -> Subject {
        let encodedCBOR: Data
        let digest: Digest
        switch self {
        case .leaf(let c, _):
            encodedCBOR = c.cborEncode
            digest = Digest(encodedCBOR)
        case .simplex(let s):
            encodedCBOR = s.taggedCBOR.cborEncode
            digest = s.digest
        case .encrypted(_, _):
            throw SimplexError.invalidOperation
        }
        
        let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: digest, nonce: nonce)
        return Subject.encrypted(encryptedMessage, digest)
    }
    
    public func decrypt(with key: SymmetricKey) throws -> Subject {
        guard
            case let .encrypted(encryptedMessage, _) = self
        else {
            throw SimplexError.invalidOperation
        }
        
        guard
            let encodedCBOR = key.decrypt(message: encryptedMessage)
        else {
            throw SimplexError.invalidKey
        }
        
        let cbor = try CBOR(encodedCBOR)
        if case CBOR.tagged(URType.simplex.tag, _) = cbor {
            let simplex = try Simplex(taggedCBOR: cbor)
            guard simplex.digest == digest else {
                throw SimplexError.invalidDigest
            }
            return .simplex(simplex)
        } else {
            guard try Digest.validate(encodedCBOR, digest: encryptedMessage.digest) else {
                throw SimplexError.invalidDigest
            }
            return .leaf(cbor, digest)
        }
    }
}
