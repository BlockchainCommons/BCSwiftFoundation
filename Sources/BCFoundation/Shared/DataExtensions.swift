//
//  DataExtensions.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation
import class CryptoSwift.SHA3

extension Data {
    public var keccak256: Data {
        let s = SHA3(variant: .keccak256)
        let r = s.calculate(for: data.bytes)
        return Data(r)
    }
}
