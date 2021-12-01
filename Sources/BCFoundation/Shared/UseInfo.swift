//
//  UseInfo.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation
@_exported import BCWally

// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md#cddl-for-coin-info
public struct UseInfo: Equatable {
    public let asset: Asset
    public let network: Network

    public init(asset: Asset = .btc, network: Network = .mainnet) {
        self.asset = asset
        self.network = network
    }
}

extension UseInfo {
    public var coinType: UInt32 {
        switch network {
        case .mainnet:
            return asset.coinType
        case .testnet:
            return 1
        }
    }
    
    public func accountDerivationPath(account: UInt32) -> DerivationPath {
        switch asset {
        case .btc:
            return DerivationPath(string: "44'/\(coinType)'/\(account)'")!
        case .eth:
            return DerivationPath(string: "44'/\(coinType)'/\(account)'/0/0")!
        }
    }
}

extension UseInfo {
    public var versionSH: UInt8 {
        precondition(asset == .btc)
        switch network {
        case .mainnet:
            return 0x05
        case .testnet:
            return 0xc4
        }
    }
    
    public var versionPKH: UInt8 {
        precondition(asset == .btc)
        switch network {
        case .mainnet:
            return 0x00
        case .testnet:
            return 0x6f
        }
    }
}
