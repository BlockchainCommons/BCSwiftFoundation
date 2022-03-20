import Foundation
import URKit
import SSKR
import CryptoKit

public struct SecureEnvelope {
    public let content: Content

    public enum Content {
        case plaintext(Data, [SecureSignature])
        case encrypted(SecureMessage, Permit)
    }

    public enum Permit {
        case symmetric
        case recipients([SecureSealedMessage])
        case share(SSKRShare)
    }
    
    public init(content: Content) {
        self.content = content
    }
}

extension SecureEnvelope {
    public init(message: SecureMessage) {
        self.init(content: .encrypted(message, .symmetric))
    }
    
    public init(plaintext: DataProvider, key: SecureMessage.Key) {
        self.init(message: SecureMessage(plaintext: plaintext, key: key))
    }
    
    public func plaintext(with key: SecureMessage.Key) -> Data? {
        guard case let(.encrypted(message, .symmetric)) = content else {
            return nil
        }
        return key.decrypt(message: message)
    }
    
    public init(inner: SecureEnvelope, key: SecureMessage.Key) {
        self.init(plaintext: inner.taggedCBOR, key: key)
    }
    
    public func inner(with key: SecureMessage.Key) -> SecureEnvelope? {
        guard
            let innerCBOR = plaintext(with: key),
            let inner = SecureEnvelope(taggedCBOR: innerCBOR)
        else {
            return nil
        }
        
        return inner
    }
}

extension SecureEnvelope {
    public init(plaintext: DataProvider) {
        self.init(content: .plaintext(plaintext.providedData, []))
    }
    
    public init(inner: SecureEnvelope) {
        self.init(plaintext: inner.taggedCBOR)
    }
    
    public init(plaintext: DataProvider, signatures: [SecureSignature]) {
        self.init(content: .plaintext(plaintext.providedData, signatures))
    }
    
    public init(inner: SecureEnvelope, signatures: [SecureSignature]) {
        self.init(plaintext: inner.taggedCBOR, signatures: signatures)
    }

    public init(plaintext: DataProvider, signers: [SecureIdentity]) {
        let signatures = signers.map {
            $0.signingPrivateKey.sign(data: plaintext)
        }
        self.init(plaintext: plaintext, signatures: signatures)
    }
    
    public init(inner: SecureEnvelope, signers: [SecureIdentity]) {
        self.init(plaintext: inner.taggedCBOR, signers: signers)
    }
    
    public init(plaintext: DataProvider, signer: SecureIdentity) {
        self.init(plaintext: plaintext, signers: [signer])
    }
    
    public init(inner: SecureEnvelope, signer: SecureIdentity) {
        self.init(plaintext: inner.taggedCBOR, signer: signer)
    }
    
    public var plaintext: Data? {
        guard case let(.plaintext(data, _)) = content else {
            return nil
        }
        return data
    }
    
    public var inner: SecureEnvelope? {
        guard let plaintext = plaintext else {
            return nil
        }
        return SecureEnvelope(taggedCBOR: plaintext)
    }
    
    public var signatures: [SecureSignature] {
        guard case let(.plaintext(_, signatures)) = content else {
            return []
        }
        return signatures
    }
    
    public func isValidSignature(_ signature: SecureSignature, key: PublicSigningKey) -> Bool {
        guard let plaintext = plaintext else {
            return false
        }
        return key.isValidSignature(signature, for: plaintext)
    }
    
    public func isValidSignature(_ signature: SecureSignature, peer: SecurePeer) -> Bool {
        isValidSignature(signature, key: peer.signingPublicKey)
    }
    
    public func hasValidSignature(with key: PublicSigningKey) -> Bool {
        signatures.contains { isValidSignature($0, key: key) }
    }
    
    public func hasValidSignature(from peer: SecurePeer) -> Bool {
        hasValidSignature(with: peer.signingPublicKey)
    }
    
    public func hasValidSignatures(with keys: [PublicSigningKey], threshold: Int? = nil) -> Bool {
        keys.filter(hasValidSignature).count >= threshold ?? keys.count
    }
    
    public func hasValidSignatures(from peers: [SecurePeer], threshold: Int? = nil) -> Bool {
        hasValidSignatures(with: peers.map { $0.signingPublicKey }, threshold: threshold)
    }
}

extension SecureEnvelope {
    public var cbor: CBOR {
        var array: [CBOR] = []
        
        switch content {
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
                try SecureSignature(taggedCBOR: $0)
            }
            self.content = .plaintext(plaintext, signatures)
        case 2:
            let message = try SecureMessage(taggedCBOR: elements[1])
            let permit = try Permit(taggedCBOR: elements[2])
            self.content = .encrypted(message, permit)
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

extension SecureEnvelope.Permit {
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
                try SecureSealedMessage(taggedCBOR: $0)
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

extension SecureEnvelope {
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
