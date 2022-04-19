import Foundation
import WolfBase
import URKit

public struct Nonce: CustomStringConvertible, Equatable, Hashable, RawRepresentable, DataProvider {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 12 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public init() {
        self.init(rawValue: SecureRandomNumberGenerator.shared.data(count: 12))!
    }

    public var bytes: [UInt8] {
        rawValue.bytes
    }
    
    public var description: String {
        rawValue.hex.flanked("Nonce(", ")")
    }
    
    public var providedData: Data {
        rawValue
    }
}

extension Nonce {
    public var untaggedCBOR: CBOR {
        CBOR.data(self.rawValue)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(rawValue) = untaggedCBOR,
            let result = Nonce(rawValue: rawValue)
        else {
            throw CBORError.invalidFormat
        }
        self = result
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(.nonce, untaggedCBOR)
    }

    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.nonce, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Nonce: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension Nonce: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Nonce {
        try Nonce(taggedCBOR: cbor)
    }
}
