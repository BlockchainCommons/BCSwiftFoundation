import Foundation
import CryptoKit
import WolfBase
import URKit

/// A Curve25519 private key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
public struct AgreementPrivateKey: CustomStringConvertible, Hashable {
    public let data: Data
    
    public init?(_ data: DataProvider) {
        let data = data.providedData
        guard data.count == 32 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.data = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
    }

    public var publicKey: AgreementPublicKey {
        AgreementPublicKey(data: cryptoKitForm.publicKey.rawRepresentation)!
    }
    
    public var description: String {
        "PrivateAgreementKey\(data)"
    }

    public var cryptoKitForm: Curve25519.KeyAgreement.PrivateKey {
        try! .init(rawRepresentation: data)
    }
}

extension AgreementPrivateKey {
    public var untaggedCBOR: CBOR {
        let type = CBOR.unsignedInt(1)
        let key = CBOR.data(self.data)
        return CBOR.array([type, key])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.agreementPrivateKey, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(data) = elements[1],
            let key = AgreementPrivateKey(data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.agreementPrivateKey, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension AgreementPrivateKey: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
