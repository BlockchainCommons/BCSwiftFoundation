//
//  SeedRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import CryptoSwift
@_exported import URKit

public struct SeedRequestBody {
    public let seedDigest: SeedDigest
    
    public var digest: Data {
        seedDigest.digest
    }
    
    public var untaggedCBOR: CBOR {
        CBOR.orderedMap([1: seedDigest.taggedCBOR])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.seedRequestBody, untaggedCBOR)
    }
    
    public init(seedDigest: SeedDigest) {
        self.seedDigest = seedDigest
    }
    
    public init(digest: Data) throws {
        self.seedDigest = try SeedDigest(digest: digest)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.map(pairs) = untaggedCBOR else {
            // Seed request doesn't contain map
            throw CBORError.invalidFormat
        }
        guard let digestItem = pairs[1] else {
            // Seed request doesn't contain digest field
            throw CBORError.invalidFormat
        }
        guard let seedDigest = try SeedDigest(taggedCBOR: digestItem) else {
            // Seed request doesn't contain valid digest
            throw CBORError.invalidFormat
        }
                
        self.init(seedDigest: seedDigest)
    }
    
    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.seedRequestBody, cbor) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: cbor)
    }
}
