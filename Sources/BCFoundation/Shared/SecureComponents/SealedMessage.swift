import Foundation
import WolfBase

/// An encrypted message that can only be opened by its intended recipient.
///
/// It is encrypted using an ephemeral private key that is thrown away, and encapsulates
/// the ephemeral public key and the receiver's public key needed for decryption.
public struct SealedMessage {
    public let message: EncryptedMessage
    public let ephemeralPublicKey: AgreementPublicKey
    
    public init(plaintext: DataProvider, receiver: Peer, aad: Data? = nil) {
        let ephemeralSender = Identity()
        let receiverPublicKey = receiver.publicAgreementKey
        let key = EncryptedMessage.sharedKey(identityPrivateKey: ephemeralSender.agreementPrivateKey, peerPublicKey: receiverPublicKey)
        self.message = key.encrypt(plaintext: plaintext, aad: aad)
        self.ephemeralPublicKey = ephemeralSender.agreementPublicKey
    }
    
    public init(message: EncryptedMessage, ephemeralPublicKey: AgreementPublicKey) {
        self.message = message
        self.ephemeralPublicKey = ephemeralPublicKey
    }
    
    public func plaintext(with identity: Identity) -> Data? {
        let key = EncryptedMessage.sharedKey(identityPrivateKey: identity.agreementPrivateKey, peerPublicKey: ephemeralPublicKey)
        return key.decrypt(message: message)
    }
    
    public static func firstPlaintext(in sealedMessages: [SealedMessage], for identity: Identity) -> Data? {
        for sealedMessage in sealedMessages {
            if let plaintext = sealedMessage.plaintext(with: identity) {
                return plaintext
            }
        }
        return nil
    }
}

extension SealedMessage {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let message = self.message.taggedCBOR
        let ephemeralPublicKey = self.ephemeralPublicKey.taggedCBOR
        
        return CBOR.array([type, message, ephemeralPublicKey])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.sealedMessage.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 3,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            let message = try? EncryptedMessage(taggedCBOR: elements[1]),
            let ephemeralPublicKey = try? AgreementPublicKey(taggedCBOR: elements[2])
        else {
            throw CBORError.invalidFormat
        }
        
        self.init(message: message, ephemeralPublicKey: ephemeralPublicKey)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.sealedMessage.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

// TODO: UR Encoding
