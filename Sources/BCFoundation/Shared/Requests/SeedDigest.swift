import Foundation
import CryptoSwift
import URKit

public struct SeedDigest {
    public let digest: Data
    
    public var untaggedCBOR: CBOR {
        CBOR.data(digest)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.seedDigest, untaggedCBOR)
    }
    
    public init(digest: Data) throws {
        guard digest.count == SHA2.Variant.sha256.digestLength else {
            throw CBORError.invalidFormat
        }
        self.digest = digest
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.data(bytes) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        try self.init(digest: bytes.data)
    }
    
    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.seedDigest, untaggedCBOR) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}
