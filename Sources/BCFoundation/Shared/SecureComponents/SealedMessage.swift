import Foundation
import WolfBase

/// An encrypted message that can only be opened by its intended recipient.
///
/// It is encrypted using an ephemeral private key that is thrown away, and encapsulates
/// the ephemeral public key and the receiver's public key needed for decryption.
public struct SealedMessage {
    public let message: Message
    public let ephemeralPublicKey: PublicAgreementKey
    public let receiverPublicKey: PublicAgreementKey
    
    public init(plaintext: DataProvider, receiver: Peer, aad: Data? = nil) {
        let ephemeralSender = Identity()
        let receiverPublicKey = receiver.publicAgreementKey
        let key = Message.sharedKey(identityPrivateKey: ephemeralSender.privateAgreementKey, peerPublicKey: receiverPublicKey)
        self.message = key.encrypt(plaintext: plaintext, aad: aad)
        self.ephemeralPublicKey = ephemeralSender.publicAgreementKey
        self.receiverPublicKey = receiverPublicKey
    }
    
    public init(message: Message, ephemeralPublicKey: PublicAgreementKey, receiverPublicKey: PublicAgreementKey) {
        self.message = message
        self.ephemeralPublicKey = ephemeralPublicKey
        self.receiverPublicKey = receiverPublicKey
    }
    
    public func plaintext(with identity: Identity) -> Data? {
        let key = Message.sharedKey(identityPrivateKey: identity.privateAgreementKey, peerPublicKey: ephemeralPublicKey)
        return key.decrypt(message: message)
    }
}

extension SealedMessage {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let message = self.message.taggedCBOR
        let ephemeralPublicKey = self.ephemeralPublicKey.taggedCBOR
        let receiverPublicKey = self.receiverPublicKey.taggedCBOR
        
        return CBOR.array([type, message, ephemeralPublicKey, receiverPublicKey])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.sealedMessage, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 4,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(messageData) = elements[1],
            let message = Message(taggedCBOR: messageData),
            case let CBOR.data(ephemeralPublicKeyData) = elements[2],
            let ephemeralPublicKey = PublicAgreementKey(taggedCBOR: ephemeralPublicKeyData),
            case let CBOR.data(receiverPublicKeyData) = elements[3],
            let receiverPublicKey = PublicAgreementKey(taggedCBOR: receiverPublicKeyData)
        else {
            throw CBORError.invalidFormat
        }
        
        self.init(message: message, ephemeralPublicKey: ephemeralPublicKey, receiverPublicKey: receiverPublicKey)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.sealedMessage, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}
