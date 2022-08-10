//
//  SeedRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit

public struct SeedRequestBody {
    public let seedDigest: SeedDigest
    
    public init(seedDigest: SeedDigest) {
        self.seedDigest = seedDigest
    }

    public var digest: Data {
        seedDigest.digest
    }
}

public extension SeedRequestBody {
    var untaggedCBOR: CBOR {
        CBOR.orderedMap([1: seedDigest.taggedCBOR])
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.seedRequestBody, untaggedCBOR)
    }
    
    init(digest: Data) throws {
        self.seedDigest = try SeedDigest(digest: digest)
    }
    
    init(untaggedCBOR: CBOR) throws {
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
    
    init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.seedRequestBody, untaggedCBOR) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

public extension SeedRequestBody {
    var envelope: Envelope {
        Envelope(function: .getSeed)
            .add(.parameter(.seedDigest, value: seedDigest))
    }
}
