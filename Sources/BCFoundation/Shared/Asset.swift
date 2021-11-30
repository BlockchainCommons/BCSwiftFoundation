//
//  Asset.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation

public enum Asset: UInt32, CaseIterable, Equatable {
    // Values from [SLIP44] with high bit turned off
    case btc = 0
    case eth = 0x3c
}

extension Asset {
    public var coinType: UInt32 {
        rawValue
    }
}

extension Asset: Identifiable {
    public var id: String {
        "asset-\(description)"
    }
}

extension Asset {
    public init?(_ symbol: String) {
        switch symbol {
        case "btc":
            self = .btc
        case "eth":
            self = .eth
        default:
            return nil
        }
    }

    public var symbol: String {
        switch self {
        case .btc:
            return "btc"
        case .eth:
            return "eth"
        }
    }
}

extension Asset {
    public var name: String {
        switch self {
        case .btc:
            return "Bitcoin"
        case .eth:
            return "Ethereum"
        }
    }
}

extension Asset: CustomStringConvertible {
    public var description: String {
        symbol
    }
}
