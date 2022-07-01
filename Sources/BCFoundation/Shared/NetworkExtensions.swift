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
        description
    }
    
    public init?(id: String) {
        switch id {
        case Network.mainnet.description:
            self = .mainnet
        case Network.testnet.description:
            self = .testnet
        default:
            return nil
        }
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
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.unsignedInt(r) = untaggedCBOR,
            let a = Network(rawValue: UInt32(r)) else {
                throw CBORError.invalidFormat
        }
        self = a
    }
}

extension Network: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(id)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let id = try container.decode(String.self)
        guard let n = Network(id: id) else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid network."))
        }
        self = n
    }
}
