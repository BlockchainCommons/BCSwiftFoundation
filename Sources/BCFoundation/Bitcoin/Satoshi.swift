//
//  Satoshi.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation

public typealias Satoshi = UInt64

public func formatBTC(_ satoshi: Satoshi) -> String {
    let decimals = Decimal(100_000_000)
    let sats = Decimal(satoshi)
    let btc = sats/decimals
    var s = btc.description
    if !s.contains(".") {
        s += ".0"
    }
    return s
}

extension Satoshi {
    public var btcFormat: String {
        formatBTC(self)
    }
}
