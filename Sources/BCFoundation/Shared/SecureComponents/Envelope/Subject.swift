import Foundation
import URKit

public indirect enum Subject {
    case leaf(CBOR, Digest)
    case envelope(Envelope)
    case encrypted(EncryptedMessage, Digest)
    case redacted(Digest)
}

extension Subject: DigestProvider {
    public var digest: Digest {
        switch self {
        case .leaf(_, let digest):
            return digest
        case .envelope(let envelope):
            return envelope.digest
        case .encrypted(_, let digest):
            return digest
        case .redacted(let digest):
            return digest
        }
    }

    public var deepDigests: Set<Digest> {
        switch self {
        case .leaf(_, let digest):
            return [digest]
        case .envelope(let envelope):
            return envelope.deepDigests
        case .encrypted(_, let digest):
            return [digest]
        case .redacted(let digest):
            return [digest]
        }
    }
}

extension Subject: Equatable {
    public static func ==(lhs: Subject, rhs: Subject) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Subject {
    public func redact() -> Subject {
        switch self {
        case .leaf(_, let digest):
            return .redacted(digest)
        case .envelope(let envelope):
            return .redacted(envelope.digest)
        case .encrypted(_, let digest):
            return .redacted(digest)
        case .redacted(_):
            return self
        }
    }
    
    public func redact(items: Set<Digest>) -> Subject {
        if items.contains(digest) {
            return .redacted(digest)
        }
        
        switch self {
        case .leaf(_, _):
            return self
        case .envelope(let envelope):
            return .envelope(envelope.redact(items: items))
        case .encrypted(_, _):
            return self
        case .redacted(_):
            return self
        }
    }
    
    public func redact(revealing items: Set<Digest>) -> Subject {
        if !items.contains(digest) {
            return .redacted(digest)
        }
        
        switch self {
        case .leaf(_, _):
            return self
        case .envelope(let envelope):
            return .envelope(envelope.redact(revealing: items))
        case .encrypted(_, _):
            return self
        case .redacted(_):
            return self
        }
    }
}

extension Subject {
    init(plaintext: CBOREncodable) {
        if let envelope = plaintext as? Envelope {
            self = .envelope(envelope)
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
    
    var envelope: Envelope? {
        guard case let .envelope(envelope) = self else {
            return nil
        }
        return envelope
    }
}

extension Subject {
    var cbor: CBOR {
        switch self {
        case .envelope(let envelope):
            return envelope.taggedCBOR
        case .leaf(let plaintext, _):
            return CBOR.tagged(.plaintext, plaintext)
        case .encrypted(let message, _):
            return message.taggedCBOR
        case .redacted(let digest):
            return digest.taggedCBOR
        }
    }
    
    init(cbor: CBOR) throws {
        if case CBOR.tagged(URType.envelope.tag, _) = cbor {
            self = try .envelope(Envelope(taggedCBOR: cbor))
        } else if case let CBOR.tagged(.plaintext, plaintext) = cbor {
            self = .leaf(plaintext, Digest(plaintext.cborEncode))
        } else if case CBOR.tagged(URType.message.tag, _) = cbor {
            let message = try EncryptedMessage(taggedCBOR: cbor)
            self = try .encrypted(message, message.digest)
        } else if case CBOR.tagged(URType.digest.tag, _) = cbor {
            self = try .redacted(Digest(taggedCBOR: cbor))
        } else {
            throw EnvelopeError.invalidFormat
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
        case .envelope(let s):
            encodedCBOR = s.taggedCBOR.cborEncode
            digest = s.digest
        case .encrypted(_, _):
            throw EnvelopeError.invalidOperation
        case .redacted(_):
            throw EnvelopeError.invalidOperation
        }
        
        let encryptedMessage = key.encrypt(plaintext: encodedCBOR, digest: digest, nonce: nonce)
        return Subject.encrypted(encryptedMessage, digest)
    }
    
    public func decrypt(with key: SymmetricKey) throws -> Subject {
        guard
            case let .encrypted(encryptedMessage, _) = self
        else {
            throw EnvelopeError.invalidOperation
        }
        
        guard
            let encodedCBOR = key.decrypt(message: encryptedMessage)
        else {
            throw EnvelopeError.invalidKey
        }
        
        let cbor = try CBOR(encodedCBOR)
        if case CBOR.tagged(URType.envelope.tag, _) = cbor {
            let envelope = try Envelope(taggedCBOR: cbor)
            guard envelope.digest == digest else {
                throw EnvelopeError.invalidDigest
            }
            return .envelope(envelope)
        } else {
            guard try Digest.validate(encodedCBOR, digest: encryptedMessage.digest) else {
                throw EnvelopeError.invalidDigest
            }
            return .leaf(cbor, digest)
        }
    }
}
