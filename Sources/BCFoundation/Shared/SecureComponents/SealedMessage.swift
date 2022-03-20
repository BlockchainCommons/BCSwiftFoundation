import Foundation

public struct SealedMessage {
    public let message: Message
    public let peer: Peer
    
    public init(plaintext: DataProvider, peer: Peer, aad: Data? = nil) {
        let ephemeralSender = Identity()
        let key = Message.sharedKey(identity: ephemeralSender, peer: peer)
        self.message = Message(plaintext: plaintext.providedData, key: key, aad: aad)
        self.peer = Peer(identity: ephemeralSender)
    }
    
    public init(message: Message, peer: Peer) {
        self.message = message
        self.peer = peer
    }
    
    public func plaintext(with identity: Identity) -> Data? {
        let key = Message.sharedKey(identity: identity, peer: peer)
        return key.decrypt(message: message)
    }
}

extension SealedMessage {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let message = self.message.taggedCBOR
        let peer = self.peer.taggedCBOR
        
        return CBOR.array([type, message, peer])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.sealedMessage, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 3,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(messageData) = elements[1],
            let message = Message(taggedCBOR: messageData),
            case let CBOR.data(peerData) = elements[2],
            let peer = Peer(taggedCBOR: peerData)
        else {
            throw CBORError.invalidFormat
        }
        
        self.init(message: message, peer: peer)
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
