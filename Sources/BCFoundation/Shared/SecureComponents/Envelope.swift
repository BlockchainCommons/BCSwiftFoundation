import Foundation
import URKit
import SSKR
import CryptoKit
import WolfBase

/// An `Envelope` allows for flexible signing, encryption, and sharding of messages.
///
/// It is an enumerated type with two options: `.plaintext` and `.encrypted`. If
/// `.plaintext` is used, it may also carry one or more signatures. If `.encrypted`
/// is used, the `EncryptedMessage` is accompanied by a `Permit` that defines the
/// conditions under which the `EncryptedMessage` may be decrypted.
///
/// To facilitate further decoding, it is recommended that the payload of an
/// `Envelope` should itself be tagged CBOR.
///
/// `Envelope` can contain as its payload another CBOR-encoded `Envelope`. This
/// facilitates both sign-then-encrypt and encrypt-then sign constructions. The
/// reason why `.plaintext` messages may be signed and `.encrypted` messages may not
/// is that generally a signer should have access to the content of what they are
/// signing, therefore this design encourages the sign-then-encrypt order of
/// operations. If encrypt-then-sign is preferred, then this is easily accomplished
/// by creating an `.encrypted` and then enclosing that envelope in an `.plaintext`
/// with the appropriate signatures.
public enum Envelope {
    case plaintext(Data, [Signature])
    case encrypted(EncryptedMessage, Permit)
}

/// A `Permit` specifies the conditions under which an `EncryptedMessage` may be decrypted.
///
/// `.symmetric` means that the `EncryptedMessage` was encrypted with a `SymmetricKey` that
/// the receiver is already expected to have.
///
/// `.recipients` facilitates multi-recipient public key cryptography by including
/// an array of `SealedMessage`, each of which is encrypted to a particular
/// recipient's public key, and which contains an ephemeral key that can be used by
/// a recipient to decrypt the main message.
///
/// `.share` facilitates social recovery by pairing an `EncryptedMessage` encrypted with an
/// ephemeral key with an `SSKRShare`, and providing for the production of a set of
/// `Envelope`s, each one including a different share. Only a threshold of shares will
/// allow the recovery of the ephemeral key and hence the decryption of the original
/// message. Each recipient of one of these `Envelope`s will have an encrypted
/// backup of the entire original `EncryptedMessage`, but only a single `SSKRShare`. A N-of-M
/// threshold of such shares will be necessary for the owner to recover the original
/// message.
public enum Permit {
    case symmetric
    case recipients([SealedMessage])
    case share(SSKRShare)
}

extension Envelope {
    public init(message: EncryptedMessage) {
        self = .encrypted(message, .symmetric)
    }
    
    public init(plaintext: DataProvider, key: SymmetricKey, aad: Data? = nil, nonce: EncryptedMessage.Nonce? = nil) {
        self.init(message: key.encrypt(plaintext: plaintext, aad: aad, nonce: nonce))
    }
    
    public func plaintext(with key: SymmetricKey) -> Data? {
        guard case let(.encrypted(message, .symmetric)) = self else {
            return nil
        }
        return key.decrypt(message: message)
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
    
    public func plaintext(for identity: Identity) -> Data? {
        guard
            case let(.encrypted(message, .recipients(sealedMessages))) = self,
            let contentKeyData = SealedMessage.firstPlaintext(in: sealedMessages, for: identity),
            let contentKey = SymmetricKey(contentKeyData),
            let plaintext = contentKey.decrypt(message: message)
        else {
            return nil
        }
        return plaintext
    }
    
    public func inner(for identity: Identity) -> Envelope? {
        guard
            let innerCBOR = plaintext(for: identity),
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
    public init(plaintext: DataProvider, schnorrSigners: [Identity], tag: Data = Data()) {
        let signatures = schnorrSigners.map {
            $0.signingPrivateKey.schnorrSign(plaintext, tag: tag)
        }
        self.init(plaintext: plaintext, signatures: signatures)
    }
    
    public init(inner: Envelope, schnorrSigners: [Identity], tag: Data = Data()) {
        self.init(plaintext: inner.taggedCBOR, schnorrSigners: schnorrSigners, tag: tag)
    }
    
    public init(plaintext: DataProvider, schnorrSigner: Identity, tag: Data = Data()) {
        self.init(plaintext: plaintext, schnorrSigners: [schnorrSigner], tag: tag)
    }
    
    public init(inner: Envelope, schnorrSigner: Identity, tag: Data = Data()) {
        self.init(plaintext: inner.taggedCBOR, schnorrSigner: schnorrSigner, tag: tag)
    }
}

extension Envelope {
    public init(plaintext: DataProvider, ecdsaSigners: [Identity]) {
        let signatures = ecdsaSigners.map {
            $0.signingPrivateKey.ecdsaSign(plaintext)
        }
        self.init(plaintext: plaintext, signatures: signatures)
    }
    
    public init(inner: Envelope, ecdsaSigners: [Identity]) {
        self.init(plaintext: inner.taggedCBOR, ecdsaSigners: ecdsaSigners)
    }
    
    public init(plaintext: DataProvider, ecdsaSigner: Identity) {
        self.init(plaintext: plaintext, ecdsaSigners: [ecdsaSigner])
    }
    
    public init(inner: Envelope, ecdsaSigner: Identity) {
        self.init(plaintext: inner.taggedCBOR, ecdsaSigner: ecdsaSigner)
    }
}

extension Envelope {
   public init(plaintext: DataProvider, recipients: [Peer]) {
        let contentKey = SymmetricKey()
        let message = contentKey.encrypt(plaintext: plaintext)
        let sealedMessages = recipients.map { peer in
            SealedMessage(plaintext: contentKey, receiver: peer)
        }
        self = .encrypted(message, .recipients(sealedMessages))
    }
    
    public init(inner: Envelope, recipients: [Peer]) {
        self.init(plaintext: inner.taggedCBOR, recipients: recipients)
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
    public static func split(plaintext: DataProvider, groupThreshold: Int, groups: [(Int, Int)]) -> [[Envelope]] {
        let ephemeralKey = SymmetricKey()
        let message = ephemeralKey.encrypt(plaintext: plaintext)
        let shares = try! SSKRGenerate(groupThreshold: groupThreshold, groups: groups, secret: ephemeralKey)
        return shares.map { groupShares in
            groupShares.map { share in .encrypted(message, .share(share)) }
        }
    }
    
    public static func plaintext(from envelopes: [Envelope]) -> Data? {
        let shares = envelopes.map { (envelope: Envelope) -> SSKRShare in
            guard case let .encrypted(_, .share(share)) = envelope else {
                fatalError()
            }
            return share
        }
        guard
            let ephemeralKey = try? SymmetricKey(SSKRCombine(shares: shares)),
            case let .encrypted(message, .share(_)) = envelopes.first,
            let plaintext = ephemeralKey.decrypt(message: message)
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
        case .encrypted(let message, let permit):
            array.append(contentsOf: [
                CBOR.unsignedInt(2),
                message.taggedCBOR,
                permit.taggedCBOR
            ])
        }
        
        return CBOR.array(array)
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
            let message = try EncryptedMessage(taggedCBOR: elements[1])
            let permit = try Permit(taggedCBOR: elements[2])
            self = .encrypted(message, permit)
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
