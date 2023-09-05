//
//  SeedRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit

public struct SeedRequestBody: TransactionRequestBody {
    public static var function = Function.getSeed
    public let seedDigest: SeedDigest
    
    public init(seedDigest: SeedDigest) {
        self.seedDigest = seedDigest
    }

    public init(seedDigest digest: Data) throws {
        self.init(seedDigest: try SeedDigest(digest: digest))
    }

    public var digest: Data {
        seedDigest.digest
    }
}

public extension SeedRequestBody {
    var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter(.seedDigest, value: seedDigest)
    }
    
    init(envelope: Envelope) throws {
        try envelope.checkFunction(Self.function)
        
        self.init(seedDigest: try envelope.extractObject(SeedDigest.self, forParameter: .seedDigest))
    }
}
