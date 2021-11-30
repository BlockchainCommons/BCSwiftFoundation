//
//  CharacterSetExtensions.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation

extension CharacterSet {
    init(with s: String) {
        var c = CharacterSet()
        c.insert(charactersIn: s)
        self = c
    }
    
    static var hexDigits: CharacterSet {
        CharacterSet(with: "0123456789abcdefABCDEF")
    }
    
    static var base58: CharacterSet {
        CharacterSet(with: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    }
    
    static var bech32: CharacterSet {
        CharacterSet(with: "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    }
    
    static var allowedInAddress: CharacterSet {
        base58.union(bech32)
    }
}
