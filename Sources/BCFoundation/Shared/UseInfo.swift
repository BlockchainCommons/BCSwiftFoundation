//
//  UseInfo.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation
import URKit

// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md#cddl-for-coin-info
public struct UseInfo: Equatable, Sendable {
    public let asset: Asset
    public let network: Network

    public init(asset: Asset = .btc, network: Network = .mainnet) {
        self.asset = asset
        self.network = network
    }
}

extension UseInfo {
    public var coinType: UInt32 {
        switch asset {
        case .btc, .eth:
            switch network {
            case .mainnet:
                return asset.coinType
            case .testnet:
                return 1
            }
        case .xtz:
            return asset.coinType
        }
    }
    
    public func accountDerivationPath(account: UInt32) -> DerivationPath {
        switch asset {
        case .btc:
            return DerivationPath(string: "44'/\(coinType)'/\(account)'")!
        case .eth:
            return DerivationPath(string: "44'/\(coinType)'/\(account)'/0/0")!
        case .xtz:
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

extension UseInfo: CBORTaggedCodable {
    public static let cborTags = [Tag.useInfo, Tag.useInfoV1]
    
    public var untaggedCBOR: CBOR {
        var a = DCBOR.Map()
        
        if asset != .btc {
            a.insert(1, asset.untaggedCBOR)
        }
        
        if network != .mainnet {
            a.insert(2, network.untaggedCBOR)
        }
        
        return a.cbor
    }

    public init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }

        let asset: Asset
        if let rawAsset = map.get(1) {
            asset = try Asset(untaggedCBOR: rawAsset)
        } else {
            asset = .btc
        }
        
        let network: Network
        if let rawNetwork = map.get(2) {
            network = try Network(untaggedCBOR: rawNetwork)
        } else {
            network = .mainnet
        }
        
        self.init(asset: asset, network: network)
    }
}

extension UseInfo: EnvelopeCodable {
    public var envelope: Envelope {
        asset.envelope
            .addAssertion(.network, network.envelope)
    }
    
    public init(envelope: Envelope) throws {
        let asset = try Asset(envelope: envelope)
        let network = try Network(envelope: envelope.object(forPredicate: .network))
        self.init(asset: asset, network: network)
    }
}
