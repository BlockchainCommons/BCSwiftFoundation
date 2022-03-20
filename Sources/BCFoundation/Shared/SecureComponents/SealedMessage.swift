import Foundation

public struct SealedMessage {
    public let message: Message
    public let ephemeralPublicKey: PublicAgreementKey
    public let receiverPublicKey: PublicAgreementKey
    
    public init(plaintext: DataProvider, receiver: Peer, aad: Data? = nil) {
        let ephemeralSender = Identity()
        let receiverPublicKey = receiver.agreementPublicKey
        let key = Message.sharedKey(identityPrivateKey: ephemeralSender.agreementPrivateKey, peerPublicKey: receiverPublicKey)
        self.message = Message(plaintext: plaintext.providedData, key: key, aad: aad)
        self.ephemeralPublicKey = ephemeralSender.agreementPublicKey
        self.receiverPublicKey = receiverPublicKey
    }
    
    public init(message: Message, ephemeralPublicKey: PublicAgreementKey, receiverPublicKey: PublicAgreementKey) {
        self.message = message
        self.ephemeralPublicKey = ephemeralPublicKey
        self.receiverPublicKey = receiverPublicKey
    }
    
    public func plaintext(with identity: Identity) -> Data? {
        let key = Message.sharedKey(identityPrivateKey: identity.agreementPrivateKey, peerPublicKey: ephemeralPublicKey)
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
