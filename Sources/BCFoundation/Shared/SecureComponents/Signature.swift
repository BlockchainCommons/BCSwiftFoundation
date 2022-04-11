import Foundation
import CryptoKit
import URKit
import WolfBase

public enum Signature {
    case schnorr(data: Data, tag: Data)
    case ecdsa(data: Data)
    
    public init?(schnorrData data: DataProvider, tag: DataProvider) {
        let data = data.providedData
        guard data.count == 64 else {
            return nil
        }
        self = .schnorr(data: data, tag: tag.providedData)
    }
    
    public init?(ecdsaData data: DataProvider) {
        let data = data.providedData
        guard data.count == 64 else {
            return nil
        }
        self = .ecdsa(data: data)
    }
}

extension Signature: Equatable {
    public static func ==(lhs: Signature, rhs: Signature) -> Bool {
        switch lhs {
        case .schnorr(let lhsData, let lhsTag):
            switch rhs {
            case .schnorr(let rhsData, let rhsTag):
                return lhsData == rhsData && lhsTag == rhsTag
            default:
                return false
            }
        case .ecdsa(let lhsData):
            switch rhs {
            case .ecdsa(let rhsData):
                return lhsData == rhsData
            default:
                return false
            }
        }
    }
}

extension Signature {
    public var cbor: CBOR {
        switch self {
        case .schnorr(let data, let tag):
            let type = CBOR.unsignedInt(1)
            let sig = CBOR.data(data)
            let tag = CBOR.data(tag)
            return CBOR.array([type, sig, tag])
        case .ecdsa(let data):
            let type = CBOR.unsignedInt(2)
            let sig = CBOR.data(data)
            return CBOR.array([type, sig])
        }
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.signature, cbor)
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
                elements.count == 3,
                case let CBOR.data(sigData) = elements[1],
                case let CBOR.data(tagData) = elements[2]
            else {
                throw CBORError.invalidFormat
            }
            self = .schnorr(data: sigData, tag: tagData)
        case 2:
            guard
                elements.count == 2,
                case let CBOR.data(sigData) = elements[1]
            else {
                throw CBORError.invalidFormat
            }
            self = .ecdsa(data: sigData)
        default:
            throw CBORError.invalidFormat
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.signature, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init(taggedCBOR: Data) throws {
        try self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension Signature: CBOREncodable {
    public var cborEncode: Data {
        taggedCBOR.cborEncode
    }
}
