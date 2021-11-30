//
//  Seed.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation

open class Seed {
    public let data: Data
    
    public init?(data: Data) {
        guard data.count <= 32 else {
            return nil
        }
        self.data = data
    }
    
    public convenience init?(hex: String) {
        guard let data = hex.hexData else {
            return nil
        }
        self.init(data: data)
    }
    
    // Copy constructor
    public init(_ seed: Seed) {
        self.data = seed.data
    }
    
    public convenience init() {
        self.init(data: SecureRandomNumberGenerator.shared.data(count: 16))!
    }
}

extension Seed {
    public var hex: String {
        data.hex
    }
}

extension Seed {
    public var bip39: BIP39 {
        BIP39(data: data)!
    }
    
    public convenience init(bip39: BIP39) {
        self.init(data: bip39.data)!
    }
}
