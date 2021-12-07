//
//  UseInfo.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation
@_exported import BCWally
@_exported import URKit

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

extension UseInfo {
    public var isDefault: Bool {
        return asset == .btc && network == .mainnet
    }
}

extension UseInfo {
    public var cbor: CBOR {
        var a: [OrderedMapEntry] = []
        
        if asset != .btc {
            a.append(.init(key: 1, value: asset.cbor))
        }
        
        if network != .mainnet {
            a.append(.init(key: 2, value: network.cbor))
        }
        
        return CBOR.orderedMap(a)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.useInfo.tag, cbor)
    }

    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor else {
            throw CBORError.invalidFormat
        }
        
        let asset: Asset
        if let rawAsset = pairs[1] {
            asset = try Asset(cbor: rawAsset)
        } else {
            asset = .btc
        }
        
        let network: Network
        if let rawNetwork = pairs[2] {
            network = try Network(cbor: rawNetwork)
        } else {
            network = .mainnet
        }
        
        self.init(asset: asset, network: network)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.useInfo.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
}
