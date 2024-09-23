//
//  SeedRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit
import SecureComponents

public struct SeedRequestBody: TransactionRequestBody {
    public static let function = Function.getSeed
    public let seedDigest: Digest
    
    public init(seedDigest: Digest) {
        self.seedDigest = seedDigest
    }

    public init(seedDigest digest: Data) throws {
        guard let digest = Digest(rawValue: digest) else {
            throw CBORError.invalidFormat
        }
        self.init(seedDigest: digest)
    }

    public var digest: Data {
        seedDigest.digest.data
    }
}

public extension SeedRequestBody {
    var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter(.seedDigest, value: Envelope(seedDigest))
    }
    
    init(envelope: Envelope) throws {
        try envelope.checkFunction(Self.function)
        
        self.init(seedDigest: try envelope.extractObject(Digest.self, forParameter: .seedDigest))
    }
}
