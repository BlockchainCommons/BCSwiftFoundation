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

extension SeedDigest: CBORTaggedCodable {
    public static var cborTag: Tag = .seedDigest
    
    public var untaggedCBOR: CBOR {
        digest.cbor
    }
    
    public init(untaggedCBOR cbor: CBOR) throws {
        try self.init(digest: Data(cbor: cbor))
    }
}
