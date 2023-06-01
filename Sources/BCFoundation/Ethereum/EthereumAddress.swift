//
//  EthereumAddress.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation

extension Ethereum {
    public struct Address: AddressProtocol {
        public let useInfo: UseInfo
        public let string: String
        
        public init?(string: String, network: Network) {
            guard
                string.count == 42,
                string.hasPrefix("0x"),
                Data(hex: string.dropFirst(2)) != nil
            else {
                return nil
            }
            self.string = string.lowercased()
            self.useInfo = UseInfo(asset: .eth, network: network)
        }
        
        public init(key: any ECKey, network: Network) {
            let hash = key.publicKey.uncompressedPublicKey.data.dropFirst().keccak256
            self.string = "0x" + hash.suffix(20).hex
            self.useInfo = UseInfo(asset: .eth, network: network)
        }
        
        public init(hdKey: HDKey) {
            self.init(key: hdKey.ecPublicKey, network: hdKey.useInfo.network)
        }

        public var description: String {
            string
        }

        public var shortString: String {
            string.dropFirst(2).prefix(4) + "..." + string.suffix(4)
        }
    }
}
