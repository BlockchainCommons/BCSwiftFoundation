//
//  EthereumAddress.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation
@_exported import BCWally

extension Ethereum {
    open class Address: AddressProtocol {
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
        
        public init(key: ECKey, network: Network) {
            let hash = key.public.uncompressed.data.dropFirst().keccak256
            self.string = "0x" + hash.suffix(20).hex
            self.useInfo = UseInfo(asset: .eth, network: network)
        }
        
        public convenience init(hdKey: HDKey) {
            self.init(key: hdKey.ecPublicKey, network: hdKey.useInfo.network)
        }

        open var description: String {
            string
        }

        public var shortString: String {
            string.dropFirst(2).prefix(4) + "..." + string.suffix(4)
        }
    }
}
