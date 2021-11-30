//
//  Network.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation
import BCWally

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
