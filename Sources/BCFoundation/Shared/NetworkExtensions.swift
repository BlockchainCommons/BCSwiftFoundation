//
//  Network.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation
import URKit

extension Network: @retroactive Identifiable {
    public var id: String {
        switch self {
        case .mainnet:
            return "network-main"
        case .testnet:
            return "network-test"
        }
    }
}

extension Network {
    public init?(id: String) {
        switch id {
        case "network-main":
            self = .mainnet
        case "network-test":
            self = .testnet
        default:
            return nil
        }
    }
}

extension Network: @retroactive CustomStringConvertible {
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
        CBOR.unsigned(UInt64(rawValue))
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.unsigned(r) = untaggedCBOR,
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

extension Network: @retroactive EnvelopeDecodable {}
extension Network: @retroactive EnvelopeEncodable {}
extension Network: @retroactive EnvelopeCodable {
    public var envelope: Envelope {
        let type: KnownValue
        switch self {
        case .mainnet:
            type = .MainNet
        case .testnet:
            type = .TestNet
        }
        return Envelope(type)
    }
    
    public init(envelope: Envelope) throws {
        switch try envelope.extractSubject(KnownValue.self) {
        case .MainNet:
            self = .mainnet
        case .TestNet:
            self = .testnet
        default:
            throw EnvelopeError.invalidFormat
        }
    }
}
