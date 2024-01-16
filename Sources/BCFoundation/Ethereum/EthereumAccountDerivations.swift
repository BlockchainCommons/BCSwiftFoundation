//
//  EthereumAccountDerivations.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation

extension AccountDerivations {
    public var ethereumAddress: Ethereum.Address? {
        guard
            useInfo.asset == .eth,
            let accountECDSAPublicKey = accountECDSAPublicKey
        else {
            return nil
        }
        return Ethereum.Address(key: accountECDSAPublicKey, network: useInfo.network)
    }
}
