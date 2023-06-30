//
//  Asset.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation
import URKit

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
            type = .bitcoin
        case .eth:
            type = .ethereum
        }
        return Envelope(type)
            .addType(.asset)
    }
    
    public init(_ envelope: Envelope) throws {
        try envelope.checkType(.asset)
        switch try envelope.extractSubject(KnownValue.self) {
        case .bitcoin:
            self = .btc
        case .ethereum:
            self = .eth
        default:
            throw EnvelopeError.invalidFormat
        }
    }
}
