import Foundation
import Blake2
import URKit

/// Implements Blake2b hashing.
///
/// https://datatracker.ietf.org/doc/rfc7693
public struct SecureDigest: CustomStringConvertible, Equatable, RawRepresentable {
    public let rawValue: Data
    public static let defaultDigestLength = 32
    
    public init(data: DataProvider, digestLength: Int = defaultDigestLength) {
        self.rawValue = try! Blake2.hash(.b2b, size: digestLength, data: data.providedData)
    }
    
    init?(rawValue: Data, digestLength: Int = defaultDigestLength) {
        guard rawValue.count == digestLength else {
            return nil
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: Data) {
        self.init(rawValue: rawValue, digestLength: Self.defaultDigestLength)
    }
    
    public var description: String {
        "SecureDigest(\(rawValue.hex))"
    }
}

extension SecureDigest {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let digest = CBOR.data(self.rawValue)
        
        return CBOR.array([type, digest])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.secureDigest.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.array(elements) = cbor else {
            throw CBORError.invalidFormat
        }
        
        guard elements.count == 2 else {
            throw CBORError.invalidFormat
        }
        
        guard
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1
        else {
            throw CBORError.invalidFormat
        }
        
        guard
            case let CBOR.data(digestData) = elements[1],
            let digest = SecureDigest(rawValue: digestData)
        else {
            throw CBORError.invalidFormat
        }
        
        self = digest
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.secureDigest.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
}

extension SecureDigest {
    public var ur: UR {
        return try! UR(type: URType.secureDigest.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.secureDigest.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
}
