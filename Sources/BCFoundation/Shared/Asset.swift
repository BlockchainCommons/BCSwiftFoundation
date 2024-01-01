//
//  Asset.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation
import URKit

public enum Asset: UInt32, CaseIterable, Equatable {
    // Values from SLIP-0044 with high bit turned off
    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    case btc = 0
    case eth = 0x3c
    case xtz = 0x6c1
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
        case "xtz":
            self = .xtz
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
        case .xtz:
            return "xtz"
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
        case .xtz:
            return "Tezos"
        }
    }
}

extension Asset: CustomStringConvertible {
    public var description: String {
        symbol
    }
}

extension Asset {
    public var untaggedCBOR: CBOR {
        CBOR.unsigned(UInt64(rawValue))
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.unsigned(r) = untaggedCBOR,
            let a = Asset(rawValue: UInt32(r))
        else {
            throw CBORError.invalidFormat
        }
        self = a
    }
}

extension Asset: EnvelopeCodable {
    public var envelope: Envelope {
        let type: KnownValue
        switch self {
        case .btc:
            type = .Bitcoin
        case .eth:
            type = .Ethereum
        case .xtz:
            type = .Tezos
        }
        return Envelope(type)
    }
    
    public init(envelope: Envelope) throws {
        switch try envelope.extractSubject(KnownValue.self) {
        case .Bitcoin:
            self = .btc
        case .Ethereum:
            self = .eth
        default:
            throw EnvelopeError.invalidFormat
        }
    }
}
