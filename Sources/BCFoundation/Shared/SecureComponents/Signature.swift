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
    public var untaggedCBOR: CBOR {
        switch self {
        case .schnorr(let data, let tag):
            if tag.isEmpty {
                return data.cbor
            } else {
                return [data.cbor, tag.cbor]
            }
        case .ecdsa(let data):
            return [1.cbor, data.cbor]
        }
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.signature, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        if
            case let CBOR.data(data) = untaggedCBOR
        {
            self = .schnorr(data: data, tag: Data())
        } else if
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2,
            case let CBOR.data(data) = elements[0],
            case let CBOR.data(tag) = elements[1]
        {
            self = .schnorr(data: data, tag: tag)
        } else if
            case let CBOR.array(elements) = untaggedCBOR,
            elements.count == 2,
            case CBOR.unsignedInt(1) = elements[0],
            case let CBOR.data(data) = elements[1]
        {
            self = .ecdsa(data: data)
        } else {
            throw CBORError.invalidFormat
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.signature, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init(taggedCBOR: Data) throws {
        try self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension Signature: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Signature: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Signature {
        try Signature(taggedCBOR: cbor)
    }
}
