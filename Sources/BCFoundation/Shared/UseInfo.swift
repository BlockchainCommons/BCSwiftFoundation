//
//  UseInfo.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation
import BCWally
import URKit

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
    public var untaggedCBOR: CBOR {
        var a: OrderedMap = [:]
        
        if asset != .btc {
            a.append(1, asset.untaggedCBOR)
        }
        
        if network != .mainnet {
            a.append(2, network.untaggedCBOR)
        }
        
        return CBOR.orderedMap(a)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.useInfo, untaggedCBOR)
    }

    public init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.orderedMap(orderedMap) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        let pairs = try orderedMap.valuesByIntKey()

        let asset: Asset
        if let rawAsset = pairs[1] {
            asset = try Asset(untaggedCBOR: rawAsset)
        } else {
            asset = .btc
        }
        
        let network: Network
        if let rawNetwork = pairs[2] {
            network = try Network(untaggedCBOR: rawNetwork)
        } else {
            network = .mainnet
        }
        
        self.init(asset: asset, network: network)
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.useInfo, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension UseInfo: CBORCodable {
    public var cbor: CBOR {
        taggedCBOR
    }
    
    public static func cborDecode(_ cbor: CBOR) throws -> UseInfo {
        try UseInfo(taggedCBOR: cbor)
    }
}
