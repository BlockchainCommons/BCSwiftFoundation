import Foundation
import CryptoSwift
import URKit

public struct SeedDigest: Equatable {
    public let digest: Data
    
    public init(digest: Data) throws {
        guard digest.count == SHA2.Variant.sha256.digestLength else {
            throw CBORError.invalidFormat
        }
        self.digest = digest
    }
}

public extension SeedDigest {
    var untaggedCBOR: CBOR {
        CBOR.data(digest)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.seedDigest, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.data(bytes) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        try self.init(digest: bytes.data)
    }
    
    init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.seedDigest, untaggedCBOR) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension SeedDigest: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> SeedDigest {
        guard let result = try SeedDigest(taggedCBOR: cbor) else {
            throw CBORError.invalidFormat
        }
        return result
    }
    
    public var cbor: CBOR {
        taggedCBOR
    }
}
