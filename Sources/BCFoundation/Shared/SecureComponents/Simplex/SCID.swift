import Foundation
import URKit

public struct SCID: CustomStringConvertible, Equatable, Hashable, RawRepresentable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 32 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public init?(_ data: Data) {
        self.init(rawValue: data)
    }
    
    public init() {
        self.init(rawValue: SecureRandomNumberGenerator.shared.data(count: 32))!
    }
    
    public var description: String {
        rawValue.hex.flanked("SCID(", ")")
    }
}

extension SCID {
    public var untaggedCBOR: CBOR {
        CBOR.data(rawValue)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.scid.tag, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = untaggedCBOR,
            let value = SCID(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = value
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.scid.tag, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
    
    public init?(taggedCBOR: Data) {
        try? self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

extension SCID {
    public var ur: UR {
        return try! UR(type: URType.scid.type, cbor: untaggedCBOR)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.scid.type else {
            throw URError.unexpectedType
        }
        let cbor = try CBOR(ur.cbor)
        try self.init(untaggedCBOR: cbor)
    }
}

extension SCID: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension SCID: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> SCID {
        try SCID(taggedCBOR: cbor)
    }
}
