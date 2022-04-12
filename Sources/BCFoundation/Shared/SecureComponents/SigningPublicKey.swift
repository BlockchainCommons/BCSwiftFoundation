import Foundation
import CryptoKit
import WolfBase

public enum SigningPublicKey {
    case schnorr(data: Data)
    case ecdsa(key: ECPublicKey)
    
    public init?(schnorrData data: DataProvider) {
        let data = data.providedData
        guard data.count == 32 else {
            return nil
        }
        self = .schnorr(data: data)
    }
    
    public init?(ecdsaData: DataProvider) {
        guard let key = ECPublicKey(ecdsaData) else {
            return nil
        }
        self = .ecdsa(key: key)
    }
    
    public func isValidSignature(_ signature: Signature, for message: DataProvider) -> Bool {
        switch self {
        case .schnorr(let keyData):
            let key = ECXOnlyPublicKey(keyData)!
            switch signature {
            case .schnorr(let sigData, let tag):
                return key.schnorrVerify(signature: sigData, tag: tag, message: message)
            default:
                return false
            }
        case .ecdsa(let key):
            switch signature {
            case .ecdsa(let sigData):
                return key.verify(message: message, signature: sigData)
            default:
                return false
            }
        }
    }
    
    public var data: Data {
        switch self {
        case .schnorr(let data):
            return data
        case .ecdsa(let key):
            return key.data
        }
    }
}

extension SigningPublicKey: Hashable {
    public static func ==(lhs: SigningPublicKey, rhs: SigningPublicKey) -> Bool {
        switch lhs {
        case .schnorr(let lhsData):
            switch rhs {
            case .schnorr(let rhsData):
                return lhsData == rhsData
            default:
                return false
            }
        case .ecdsa(let lhsKey):
            switch rhs {
            case .ecdsa(let rhsKey):
                return lhsKey == rhsKey
            default:
                return false
            }
        }
    }
    
    public func hash(into hasher: inout Hasher) {
        switch self {
        case .schnorr(let data):
            hasher.combine(data)
        case .ecdsa(let key):
            hasher.combine(key)
        }
    }
}

extension SigningPublicKey {
    public var untaggedCBOR: CBOR {
        switch self {
        case .schnorr(let data):
            let type = CBOR.unsignedInt(1)
            let data = CBOR.data(data)
            return CBOR.array([type, data])
        case .ecdsa(let key):
            let type = CBOR.unsignedInt(2)
            let data = CBOR.data(key.data)
            return CBOR.array([type, data])
        }
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.signingPublicKey, untaggedCBOR)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.array(elements) = cbor,
            elements.count > 1,
            case let CBOR.unsignedInt(type) = elements[0]
        else {
            throw CBORError.invalidFormat
        }
        
        switch type {
        case 1:
            guard
                case let CBOR.data(data) = elements[1]
            else {
                throw CBORError.invalidFormat
            }
            self = .schnorr(data: data)
        case 2:
            guard
                case let CBOR.data(data) = elements[1],
                let key = ECPublicKey(data)
            else {
                throw CBORError.invalidFormat
            }
            self = .ecdsa(key: key)
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.signingPublicKey, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SigningPublicKey: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}
