import Foundation
import Blake2
import URKit
import WolfBase

/// A cryptographically secure digest.
///
/// Implemented with Blake2b hashing.
///
/// https://datatracker.ietf.org/doc/rfc7693
public struct Digest: CustomStringConvertible, Equatable, RawRepresentable {
    public let rawValue: Data
    public static let defaultDigestLength = 32
    
    public init(_ data: DataProvider, digestLength: Int = defaultDigestLength) {
        self.rawValue = try! Blake2.hash(.b2b, size: digestLength, data: data.providedData)
    }
    
    public init?(_ data: DataProvider, includeDigest: Bool, digestLength: Int = defaultDigestLength) {
        guard includeDigest else {
            return nil
        }
        self.init(data, digestLength: digestLength)
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
        "Digest(\(rawValue.hex))"
    }
    
    public func validate(_ data: DataProvider) -> Bool {
        self == Digest(data, digestLength: self.rawValue.count)
    }
    
    public static func validate(_ data: DataProvider, digest: Digest?) -> Bool {
        guard let digest = digest else {
            return true
        }
        return digest.validate(data)
    }
}

extension Digest {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let digest = CBOR.data(self.rawValue)
        
        return CBOR.array([type, digest])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.digest.tag, cbor)
    }
    
    public static func optionalTaggedCBOR(_ digest: Digest?) -> CBOR {
        guard let digest = digest else {
            return CBOR.null
        }
        return digest.taggedCBOR
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
            let digest = Digest(rawValue: digestData)
        else {
            throw CBORError.invalidFormat
        }
        
        self = digest
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.digest.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
    
    public init?(optionalTaggedCBOR cbor: CBOR) throws {
        guard cbor != .null else {
            return nil
        }
        try self.init(taggedCBOR: cbor)
    }
}

extension Digest {
    public var ur: UR {
        return try! UR(type: URType.digest.type, cbor: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.digest.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(cbor: cbor)
    }
}
