import Foundation
import URKit
import SSKR
import CryptoKit
import WolfBase

public enum Envelope {
    case plaintext(Data, [Signature])
    case encrypted(EncryptedMessage, Permit, Digest?)
}

public enum Permit {
    case symmetric
    case recipients([SealedMessage])
    case share(SSKRShare)
}

extension Envelope {
    public init(message: EncryptedMessage, includeDigest: Bool = true) {
        let digest = Self.makeDigest(message: message, includeDigest: includeDigest)
        self = .encrypted(message, .symmetric, digest)
    }
    
    public init(plaintext: DataProvider, key: SymmetricKey, aad: Data? = nil, nonce: EncryptedMessage.Nonce? = nil) {
        self.init(message: key.encrypt(plaintext: plaintext, aad: aad, nonce: nonce))
    }
    
    public func plaintext(with key: SymmetricKey) -> Data? {
        guard case let(.encrypted(message, .symmetric, digest)) = self else {
            return nil
        }
        guard
            let data = key.decrypt(message: message),
            Self.checkDigest(message: message, digest: digest)
        else {
            return nil
        }
        return data
    }
    
    public init(inner: Envelope, key: SymmetricKey) {
        self.init(plaintext: inner.taggedCBOR, key: key)
    }
    
    public func inner(with key: SymmetricKey) -> Envelope? {
        guard
            let innerCBOR = plaintext(with: key),
            let inner = Envelope(taggedCBOR: innerCBOR)
        else {
            return nil
        }
        
        return inner
    }
    
    static func makeDigest(message: EncryptedMessage, includeDigest: Bool) -> Digest? {
        guard includeDigest else {
            return nil
        }
        return message.digest
    }
    
    static func checkDigest(message: EncryptedMessage, digest: Digest?) -> Bool {
        guard let digest = digest else {
            return true
        }
        guard message.digest == digest else {
            return false
        }
        return true
    }
    
    public func plaintext(for profile: Profile) -> Data? {
        guard
            case let(.encrypted(message, .recipients(sealedMessages), digest)) = self,
            let contentKeyData = SealedMessage.firstPlaintext(in: sealedMessages, for: profile),
            let contentKey = SymmetricKey(contentKeyData),
            let plaintext = contentKey.decrypt(message: message),
            Self.checkDigest(message: message, digest: digest)
        else {
            return nil
        }
        return plaintext
    }
    
    public func inner(for profile: Profile) -> Envelope? {
        guard
            let innerCBOR = plaintext(for: profile),
            let inner = Envelope(taggedCBOR: innerCBOR)
        else {
            return nil
        }
        
        return inner
    }
}

extension Envelope {
    public init(plaintext: DataProvider) {
        self = .plaintext(plaintext.providedData, [])
    }
    
    public init(inner: Envelope) {
        self.init(plaintext: inner.taggedCBOR)
    }
    
    public init(plaintext: DataProvider, signatures: [Signature]) {
        self = .plaintext(plaintext.providedData, signatures)
    }
    
    public init(inner: Envelope, signatures: [Signature]) {
        self.init(plaintext: inner.taggedCBOR, signatures: signatures)
    }
}

extension Envelope {
    public init(plaintext: DataProvider, schnorrSigners: [Profile], tag: Data = Data()) {
        let signatures = schnorrSigners.map {
            $0.signingPrivateKey.schnorrSign(plaintext, tag: tag)
        }
        self.init(plaintext: plaintext, signatures: signatures)
    }
    
    public init(inner: Envelope, schnorrSigners: [Profile], tag: Data = Data()) {
        self.init(plaintext: inner.taggedCBOR, schnorrSigners: schnorrSigners, tag: tag)
    }
    
    public init(plaintext: DataProvider, schnorrSigner: Profile, tag: Data = Data()) {
        self.init(plaintext: plaintext, schnorrSigners: [schnorrSigner], tag: tag)
    }
    
    public init(inner: Envelope, schnorrSigner: Profile, tag: Data = Data()) {
        self.init(plaintext: inner.taggedCBOR, schnorrSigner: schnorrSigner, tag: tag)
    }
}

extension Envelope {
    public init(plaintext: DataProvider, ecdsaSigners: [Profile]) {
        let signatures = ecdsaSigners.map {
            $0.signingPrivateKey.ecdsaSign(plaintext)
        }
        self.init(plaintext: plaintext, signatures: signatures)
    }
    
    public init(inner: Envelope, ecdsaSigners: [Profile]) {
        self.init(plaintext: inner.taggedCBOR, ecdsaSigners: ecdsaSigners)
    }
    
    public init(plaintext: DataProvider, ecdsaSigner: Profile) {
        self.init(plaintext: plaintext, ecdsaSigners: [ecdsaSigner])
    }
    
    public init(inner: Envelope, ecdsaSigner: Profile) {
        self.init(plaintext: inner.taggedCBOR, ecdsaSigner: ecdsaSigner)
    }
}

extension Envelope {
    public init(plaintext: DataProvider, recipients: [Peer], contentKey: SymmetricKey = .init(), includeDigest: Bool = true) {
        let message = contentKey.encrypt(plaintext: plaintext)
        let sealedMessages = recipients.map { peer in
            SealedMessage(plaintext: contentKey, receiver: peer)
        }
        let digest = Self.makeDigest(message: message, includeDigest: includeDigest)
        self = .encrypted(message, .recipients(sealedMessages), digest)
    }
    
    public init(inner: Envelope, recipients: [Peer], contentKey: SymmetricKey = .init()) {
        self.init(plaintext: inner.taggedCBOR, recipients: recipients, contentKey: contentKey)
    }
    
    public var plaintext: Data? {
        guard case let(.plaintext(data, _)) = self else {
            return nil
        }
        return data
    }
    
    public var inner: Envelope? {
        guard let plaintext = plaintext else {
            return nil
        }
        return Envelope(taggedCBOR: plaintext)
    }
    
    public var signatures: [Signature] {
        guard case let(.plaintext(_, signatures)) = self else {
            return []
        }
        return signatures
    }
    
    public func isValidSignature(_ signature: Signature, key: SigningPublicKey) -> Bool {
        guard let plaintext = plaintext else {
            return false
        }
        return key.isValidSignature(signature, for: plaintext)
    }
    
    public func isValidSignature(_ signature: Signature, peer: Peer) -> Bool {
        isValidSignature(signature, key: peer.signingPublicKey)
    }
    
    public func hasValidSignature(key: SigningPublicKey) -> Bool {
        signatures.contains { isValidSignature($0, key: key) }
    }
    
    public func hasValidSignature(from peer: Peer) -> Bool {
        hasValidSignature(key: peer.signingPublicKey)
    }
    
    public func hasValidSignatures(with keys: [SigningPublicKey], threshold: Int? = nil) -> Bool {
        keys.filter(hasValidSignature).count >= threshold ?? keys.count
    }
    
    public func hasValidSignatures(from peers: [Peer], threshold: Int? = nil) -> Bool {
        hasValidSignatures(with: peers.map { $0.signingPublicKey }, threshold: threshold)
    }
}

extension Envelope {
    public static func split(
        plaintext: DataProvider,
        groupThreshold: Int,
        groups: [(Int, Int)],
        contentKey: SymmetricKey = .init(),
        includeDigest: Bool = true
    ) -> [[Envelope]] {
        let message = contentKey.encrypt(plaintext: plaintext)
        let digest = Self.makeDigest(message: message, includeDigest: includeDigest)
        let shares = try! SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: contentKey)
        return shares.map { groupShares in
            groupShares.map { share in .encrypted(message, .share(share), digest) }
        }
    }
    
    public static func plaintext(from envelopes: [Envelope]) -> Data? {
        let shares = envelopes.map { (envelope: Envelope) -> SSKRShare in
            guard case let .encrypted(_, .share(share), _) = envelope else {
                fatalError()
            }
            return share
        }
        guard
            let contentKey = try? SymmetricKey(SSKRCombine(shares: shares)),
            case let .encrypted(message, .share(_), digest) = envelopes.first,
            Self.checkDigest(message: message, digest: digest),
            let plaintext = contentKey.decrypt(message: message)
        else {
            return nil
        }
        return plaintext
    }
}

extension Envelope {
    public var cbor: CBOR {
        var array: [CBOR] = []
        
        switch self {
        case .plaintext(let data, let signatures):
            array.append(contentsOf: [
                CBOR.unsignedInt(1),
                CBOR.data(data),
                CBOR.array(signatures.map { $0.taggedCBOR })
            ])
        case .encrypted(let message, let permit, let digest):
            array.append(contentsOf: [
                CBOR.unsignedInt(2),
                message.taggedCBOR,
                permit.taggedCBOR,
                Self.encodeDigestCBOR(digest: digest)
            ])
        }
        
        return CBOR.array(array)
    }
    
    static func encodeDigestCBOR(digest: Digest?) -> CBOR {
        digest?.taggedCBOR ?? CBOR.null
    }
    
    static func decodeDigestCBOR(cbor: CBOR) throws -> Digest? {
        switch cbor {
        case .null:
            return nil
        default:
            return try Digest(taggedCBOR: cbor)
        }
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.envelope.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count >= 1,
            case let CBOR.unsignedInt(type) = elements[0]
        else {
            throw CBORError.invalidFormat
        }
        
        switch type {
        case 1:
            guard
                elements.count == 3,
                case let CBOR.data(plaintext) = elements[1],
                case let CBOR.array(signatureItems) = elements[2]
            else {
                throw CBORError.invalidFormat
            }
            let signatures = try signatureItems.map {
                try Signature(taggedCBOR: $0)
            }
            self = .plaintext(plaintext, signatures)
        case 2:
            guard elements.count >= 3 else {
                throw CBORError.invalidFormat
            }
            let message = try EncryptedMessage(taggedCBOR: elements[1])
            let permit = try Permit(taggedCBOR: elements[2])
            let digest: Digest?
            if elements.count >= 4 {
                digest = try Self.decodeDigestCBOR(cbor: elements[3])
            } else {
                digest = nil
            }
            guard
                elements.count <= 4,
                Self.checkDigest(message: message, digest: digest)
            else {
                throw CBORError.invalidFormat
            }
            self = .encrypted(message, permit, digest)
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.envelope.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
}

extension Permit {
    public var cbor: CBOR {
        var array: [CBOR] = []
        
        switch self {
        case .symmetric:
            array.append(contentsOf: [
                CBOR.unsignedInt(1)
            ])
        case .recipients(let sealedMessages):
            array.append(contentsOf: [
                CBOR.unsignedInt(2),
                CBOR.array(sealedMessages.map { $0.taggedCBOR })
            ])
        case .share(let sskrShare):
            array.append(contentsOf: [
                CBOR.unsignedInt(3),
                sskrShare.taggedCBOR
            ])
        }
        
        return CBOR.array(array)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.permit, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count >= 1,
            case let CBOR.unsignedInt(type) = elements[0]
        else {
            throw CBORError.invalidFormat
        }
        
        switch type {
        case 1:
            self = .symmetric
        case 2:
            guard
                case let CBOR.array(sealedMessageItems) = elements[1]
            else {
                throw CBORError.invalidFormat
            }
            let sealedMessages = try sealedMessageItems.map {
                try SealedMessage(taggedCBOR: $0)
            }
            self = .recipients(sealedMessages)
        case 3:
            self = try .share(SSKRShare(taggedCBOR: elements[1]))
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.permit, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension Envelope {
    public var ur: UR {
        return try! UR(type: URType.envelope.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.envelope.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
