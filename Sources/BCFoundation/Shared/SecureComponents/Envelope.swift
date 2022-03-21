import Foundation
import URKit
import SSKR
import CryptoKit
import WolfBase

/// An `Envelope` (serialized as `ur:crypto-envelope`) allows for flexible signing,
/// encryption, and sharding of messages.
///
/// It is an enumerated type with two options: `.plaintext` and `.encrypted`. If
/// `.plaintext` is used, it may also carry one or more signatures. If `.encrypted`
/// is used, the encrypted `Message` is accompanied by a `Permit` that defines the
/// conditions under which the `Message` may be decrypted.
///
/// To facilitate further decoding, it is recommended that the payload of an
/// `Envelope` should itself be well-formed tagged CBOR.
///
/// `Envelope` can contain as its payload another CBOR-encoded `Envelope`. This
/// facilitates both sign-then-encrypt and encrypt-then sign constructions. The
/// reason why `.plaintext` messages may be signed and `.encrypted` messages may not
/// is that generally a signer should have access to the content of what they are
/// signing, and encourages the sign-then-encrypt order of operations. If
/// encrypt-then-sign is preferred, then this is easily accomplished by creating an
/// `.encrypted` and then enclosing that envelope in an `.plaintext` with the
/// appropriate signatures.
public enum Envelope {
    case plaintext(Data, [Signature])
    case encrypted(Message, Permit)
}

/// A `Permit` specifies the conditions under which a `Message` may be decrypted.
///
/// `.symmetric` means that the `Message` was encrypted with a symmetric
/// `Message.Key` that the receiver is already expected to have.
///
/// `.recipients` facilitates multi-recipient public key cryptography by including
/// an array of `SealedMessage`, each of which is encrypted to a particular
/// recipient's public key, and which contains an ephemeral key that can be used by
/// the recipient to decrypt the main message.
///
/// `.share` facilitates social recovery by pairing a `Message` encrypted with an
/// ephemeral key with an `SSKRShare`, and providing for the production of a set of
/// envelopes each with a different share. Only a threshold of shares will allow the
/// recovery of the ephemeral key and hence the decryption of the original message.
/// Each recipient of one of these envelopes will have a backup of the entire original
/// `Message`, but only a single `SSKRShare`.
public enum Permit {
    case symmetric
    case recipients([SealedMessage])
    case share(SSKRShare)
}

extension Envelope {
    public init(message: Message) {
        self = .encrypted(message, .symmetric)
    }
    
    public init(plaintext: DataProvider, key: Message.Key) {
        self.init(message: key.encrypt(plaintext: plaintext))
    }
    
    public func plaintext(with key: Message.Key) -> Data? {
        guard case let(.encrypted(message, .symmetric)) = self else {
            return nil
        }
        return key.decrypt(message: message)
    }
    
    public init(inner: Envelope, key: Message.Key) {
        self.init(plaintext: inner.taggedCBOR, key: key)
    }
    
    public func inner(with key: Message.Key) -> Envelope? {
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
            let sealedMessage = sealedMessages.first(where: { $0.receiverPublicKey == identity.publicAgreementKey }),
            let contentKeyData = sealedMessage.plaintext(with: identity),
            let contentKey = Message.Key(rawValue: contentKeyData),
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

    public init(plaintext: DataProvider, signers: [Identity]) {
        let signatures = signers.map {
            $0.privateSigningKey.sign(data: plaintext)
        }
        self.init(plaintext: plaintext, signatures: signatures)
    }
    
    public init(inner: Envelope, signers: [Identity]) {
        self.init(plaintext: inner.taggedCBOR, signers: signers)
    }
    
    public init(plaintext: DataProvider, signer: Identity) {
        self.init(plaintext: plaintext, signers: [signer])
    }
    
    public init(inner: Envelope, signer: Identity) {
        self.init(plaintext: inner.taggedCBOR, signer: signer)
    }
    
    public init(plaintext: DataProvider, recipients: [Peer]) {
        let contentKey = Message.Key()
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
    
    public func isValidSignature(_ signature: Signature, key: PublicSigningKey) -> Bool {
        guard let plaintext = plaintext else {
            return false
        }
        return key.isValidSignature(signature, for: plaintext)
    }
    
    public func isValidSignature(_ signature: Signature, peer: Peer) -> Bool {
        isValidSignature(signature, key: peer.publicSigningKey)
    }
    
    public func hasValidSignature(with key: PublicSigningKey) -> Bool {
        signatures.contains { isValidSignature($0, key: key) }
    }
    
    public func hasValidSignature(from peer: Peer) -> Bool {
        hasValidSignature(with: peer.publicSigningKey)
    }
    
    public func hasValidSignatures(with keys: [PublicSigningKey], threshold: Int? = nil) -> Bool {
        keys.filter(hasValidSignature).count >= threshold ?? keys.count
    }
    
    public func hasValidSignatures(from peers: [Peer], threshold: Int? = nil) -> Bool {
        hasValidSignatures(with: peers.map { $0.publicSigningKey }, threshold: threshold)
    }
}

extension Envelope {
    public static func split(plaintext: DataProvider, groupThreshold: Int, groups: [(Int, Int)]) -> [[Envelope]] {
        let ephemeralKey = Message.Key()
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
            let ephemeralKey = try? Message.Key(rawValue: SSKRCombine(shares: shares)),
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
        CBOR.tagged(URType.secureEnvelope.tag, cbor)
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
            let message = try Message(taggedCBOR: elements[1])
            let permit = try Permit(taggedCBOR: elements[2])
            self = .encrypted(message, permit)
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.secureEnvelope.tag, cbor) = taggedCBOR else {
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
        return try! UR(type: URType.secureEnvelope.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.secureEnvelope.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
