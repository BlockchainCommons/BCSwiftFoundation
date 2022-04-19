import Foundation
import URKit

extension URL {
    public var untaggedCBOR: CBOR {
        CBOR.utf8String(absoluteString)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.utf8String(string) = untaggedCBOR,
            let result = URL(string: string)
        else {
            throw CBORError.invalidFormat
        }
        self = result
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.uri, untaggedCBOR)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard
            case let CBOR.tagged(.uri, untaggedCBOR) = taggedCBOR
        else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension URL: CBOREncodable {
    public var cbor: CBOR {
        taggedCBOR
    }
}

extension URL: CBORDecodable {
    public static func cborDecode(_ cbor: CBOR) throws -> URL {
        try URL(taggedCBOR: cbor)
    }
}
