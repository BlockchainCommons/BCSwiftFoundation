import Foundation

public struct SecureSealedMessage {
    public let message: SecureMessage
    public let peer: SecurePeer
    
    public init(plaintext: Data, peer: SecurePeer, aad: Data? = nil) {
        let ephemeralIdentity = SecureIdentity()
        let key = SecureMessage.sharedKey(identity: ephemeralIdentity, peer: peer)
        self.message = SecureMessage(plaintext: plaintext, key: key, aad: aad)
        self.peer = peer
    }
    
    public init(message: SecureMessage, peer: SecurePeer) {
        self.message = message
        self.peer = peer
    }
}

extension SecureSealedMessage {
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
            let message = SecureMessage(taggedCBOR: messageData),
            case let CBOR.data(peerData) = elements[2],
            let peer = SecurePeer(taggedCBOR: peerData)
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
