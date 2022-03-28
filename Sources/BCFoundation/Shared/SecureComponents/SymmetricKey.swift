import Foundation
import protocol WolfBase.DataProvider
import CryptoSwift

/// A symmetric key for encryption and decryption of IETF-ChaCha20-Poly1305 messages.
///
/// https://datatracker.ietf.org/doc/html/rfc8439
public struct SymmetricKey: CustomStringConvertible, Equatable, Hashable, RawRepresentable, DataProvider {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public init() {
        self.init(rawValue: SecureRandomNumberGenerator.shared.data(count: 32))!
    }
    
    public var bytes: [UInt8] {
        rawValue.bytes
    }
    
    public var description: String {
        rawValue.description.flanked("Key(", ")")
    }
    
    public func encrypt(plaintext: DataProvider, aad: Data? = nil, nonce: Message.Nonce? = nil) -> Message {
        let plaintext = plaintext.providedData
        let aad = aad ?? Data()
        let nonce = nonce ?? Message.Nonce()
        let (ciphertext, auth) = try! AEADChaCha20Poly1305.encrypt(plaintext.bytes, key: self.bytes, iv: nonce.bytes, authenticationHeader: aad.bytes)
        return Message(ciphertext: Data(ciphertext), aad: aad, nonce: nonce, auth: Message.Auth(rawValue: Data(auth))!)!
    }
    
    public func decrypt(message: Message) -> Data? {
        guard let (plaintext, success) =
                try? AEADChaCha20Poly1305.decrypt(message.ciphertext.bytes, key: self.bytes, iv: message.nonce.bytes, authenticationHeader: message.aad.bytes, authenticationTag: message.auth.bytes),
                success
        else {
            return nil
        }
        return Data(plaintext)
    }
    
    public var providedData: Data {
        rawValue
    }
}
