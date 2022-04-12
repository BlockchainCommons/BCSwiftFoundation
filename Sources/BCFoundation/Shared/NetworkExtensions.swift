//
//  Network.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation
@_exported import BCWally
@_exported import URKit

extension Network: Identifiable {
    public var id: String {
        "network-\(description)"
    }
}

extension Network: CustomStringConvertible {
    public var description: String {
        switch self {
        case .mainnet:
            return "main"
        case .testnet:
            return "test"
        }
    }
}

extension Network {
    public var untaggedCBOR: CBOR {
        CBOR.unsignedInt(UInt64(rawValue))
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.unsignedInt(r) = cbor,
            let a = Network(rawValue: UInt32(r)) else {
                throw CBORError.invalidFormat
        }
        self = a
    }
}
