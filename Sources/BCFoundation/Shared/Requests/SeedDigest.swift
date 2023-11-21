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
    public static var cborTags = [Tag.seedDigest]
    
    public var untaggedCBOR: CBOR {
        digest.cbor
    }
    
    public init(untaggedCBOR cbor: CBOR) throws {
        try self.init(digest: Data(cbor: cbor))
    }
}

extension SeedDigest: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(envelope: Envelope) throws {
        self = try envelope.subject.extractSubject(Self.self)
    }
}
