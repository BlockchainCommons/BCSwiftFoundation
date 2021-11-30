//
//  BitcoinAccountExtensions.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation

extension Account {
    public func bitcoinAddress(type: Bitcoin.Address.AddressType) -> Bitcoin.Address? {
        guard
            useInfo.asset == .btc,
            let accountKey = accountKey
        else {
            return nil
        }
        return Bitcoin.Address(hdKey: accountKey, type: type)
    }
}
