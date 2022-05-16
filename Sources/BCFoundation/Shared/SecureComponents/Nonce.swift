import Foundation
import WolfBase
import URKit

public struct Nonce: CustomStringConvertible, Equatable, Hashable, DataProvider {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == 12 else {
            return nil
        }
        self.data = data
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 12))!
    }

    public var bytes: [UInt8] {
        data.bytes
    }
    
    public var description: String {
        data.hex.flanked("Nonce(", ")")
    }
    
    public var providedData: Data {
        data
    }
}

extension Nonce {
    public var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR,
            let result = Nonce(data)
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
