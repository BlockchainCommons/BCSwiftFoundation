import Foundation

public struct SealedMessage {
    public let message: Message
    public let peer: Peer
    
    public init(plaintext: Data, peer: Peer, aad: Data? = nil) {
        let ephemeralIdentity = Identity()
        let key = Message.sharedKey(identity: ephemeralIdentity, peer: peer)
        self.message = Message(plaintext: plaintext, key: key, aad: aad)
        self.peer = peer
    }
    
    public init(message: Message, peer: Peer) {
        self.message = message
        self.peer = peer
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
