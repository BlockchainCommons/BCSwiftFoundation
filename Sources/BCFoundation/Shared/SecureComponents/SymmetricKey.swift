import Foundation
import protocol WolfBase.DataProvider
import CryptoSwift

/// A symmetric key for encryption and decryption of IETF-ChaCha20-Poly1305 messages.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
public struct SymmetricKey: CustomStringConvertible, Equatable, Hashable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))!
    }
    
    public var bytes: [UInt8] {
        data.bytes
    }
    
    public var description: String {
        data.description.flanked("Key(", ")")
    }
    
    public func encrypt(plaintext: DataProvider, aad: Data? = nil, nonce: EncryptedMessage.Nonce? = nil) -> EncryptedMessage {
        let plaintext = plaintext.providedData
        let aad = aad ?? Data()
        let nonce = nonce ?? EncryptedMessage.Nonce()
        let (ciphertext, auth) = try! AEADChaCha20Poly1305.encrypt(plaintext.bytes, key: self.bytes, iv: nonce.bytes, authenticationHeader: aad.bytes)
        return EncryptedMessage(ciphertext: Data(ciphertext), aad: aad, nonce: nonce, auth: EncryptedMessage.Auth(rawValue: Data(auth))!)!
    }
    
    public func decrypt(message: EncryptedMessage) -> Data? {
        guard let (plaintext, success) =
                try? AEADChaCha20Poly1305.decrypt(message.ciphertext.bytes, key: self.bytes, iv: message.nonce.bytes, authenticationHeader: message.aad.bytes, authenticationTag: message.auth.bytes),
                success
        else {
            return nil
        }
        return Data(plaintext)
    }
    
    public var providedData: Data {
        data
    }
}

extension SymmetricKey {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let key = CBOR.data(self.data)
        return CBOR.array([type, key])
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.symmetricKey.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 2,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(data) = elements[1],
            let key = SymmetricKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.symmetricKey.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SymmetricKey {
    public var ur: UR {
        return try! UR(type: URType.symmetricKey.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.symmetricKey.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
}

extension SymmetricKey: CBOREncodable {
    public var cborEncode: Data {
        taggedCBOR.cborEncode
    }
}
