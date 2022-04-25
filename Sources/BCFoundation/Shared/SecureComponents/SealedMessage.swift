import Foundation
import WolfBase
import URKit

/// An encrypted message that can only be opened by its intended recipient.
///
/// It is encrypted using an ephemeral private key that is thrown away, and encapsulates
/// the ephemeral public key and the receiver's public key needed for decryption.
public struct SealedMessage {
    public let message: EncryptedMessage
    public let ephemeralPublicKey: AgreementPublicKey
    
    public init(plaintext: DataProvider, recipient: PublicKeyBase, aad: Data? = nil) {
        let ephemeralSender = PrivateKeyBase()
        let recipientPublicKey = recipient.agreementPublicKey
        let key = EncryptedMessage.sharedKey(agreementPrivateKey: ephemeralSender.agreementPrivateKey, agreementPublicKey: recipientPublicKey)
        self.message = key.encrypt(plaintext: plaintext, aad: aad)
        self.ephemeralPublicKey = ephemeralSender.agreementPrivateKey.publicKey
    }
    
    public init(message: EncryptedMessage, ephemeralPublicKey: AgreementPublicKey) {
        self.message = message
        self.ephemeralPublicKey = ephemeralPublicKey
    }
    
    public func plaintext(with privateKeys: PrivateKeyBase) -> Data? {
        let key = EncryptedMessage.sharedKey(agreementPrivateKey: privateKeys.agreementPrivateKey, agreementPublicKey: ephemeralPublicKey)
        return key.decrypt(message: message)
    }
    
    public static func firstPlaintext(in sealedMessages: [SealedMessage], for privateKeys: PrivateKeyBase) -> Data? {
        for sealedMessage in sealedMessages {
            if let plaintext = sealedMessage.plaintext(with: privateKeys) {
                return plaintext
            }
        }
        return nil
    }
}

extension SealedMessage {
    public var untaggedCBOR: CBOR {
        let message = self.message.taggedCBOR
        let ephemeralPublicKey = self.ephemeralPublicKey.taggedCBOR
        
        return [message, ephemeralPublicKey]
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.sealedMessage.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2,
            let message = try? EncryptedMessage(taggedCBOR: elements[0]),
            let ephemeralPublicKey = try? AgreementPublicKey(taggedCBOR: elements[1])
        else {
            throw CBORError.invalidFormat
        }
        
        self.init(message: message, ephemeralPublicKey: ephemeralPublicKey)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.sealedMessage.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SealedMessage: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension SealedMessage: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> SealedMessage {
        try SealedMessage(taggedCBOR: cbor)
    }
}
