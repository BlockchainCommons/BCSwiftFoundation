//
//  EthereumAccountExtensions.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation

extension Account {
    public var ethereumAddress: Ethereum.Address? {
        guard
            useInfo.asset == .eth,
            let accountECPublicKey = accountECPublicKey
        else {
            return nil
        }
        return Ethereum.Address(key: accountECPublicKey, network: useInfo.network)
    }
}
