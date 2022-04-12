import Foundation
import CryptoKit
import WolfBase

/// A Curve25519 public key used for X25519 key agreement.
///
/// https://datatracker.ietf.org/doc/html/rfc7748
public struct AgreementPublicKey: CustomStringConvertible, Hashable {
    public let data: Data
    
    public init?(data: DataProvider) {
        let data = data.providedData
        guard
            data.count == 32
        else {
            return nil
        }
        self.data = data
    }
    
    public var description: String {
        "AgreementPublicKey\(data.hex)"
    }
    
    public var cryptoKitForm: Curve25519.KeyAgreement.PublicKey {
        try! .init(rawRepresentation: data)
    }
}

extension AgreementPublicKey {
    public var untaggedCBOR: CBOR {
        let type = CBOR.unsignedInt(1)
        let key = CBOR.data(self.data)
        return CBOR.array([type, key])
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.agreementPublicKey, untaggedCBOR)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count == 2,
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(data) = elements[1],
            let key = AgreementPublicKey(data: data)
        else {
            throw CBORError.invalidFormat
        }
        self = key
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.agreementPublicKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension AgreementPublicKey: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
