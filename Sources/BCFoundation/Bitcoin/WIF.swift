//
//  WIF.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
@_exported import BCWally

public struct WIF : CustomStringConvertible {
    public let key: ECPrivateKey
    public let network: Network
    public let isPublicKeyCompressed: Bool
    
    public init(key: ECPrivateKey, network: Network, isPublicKeyCompressed: Bool = true) {
        self.key = key
        self.network = network
        self.isPublicKeyCompressed = isPublicKeyCompressed
    }

    public init?(_ wif: String) {
        guard var bytes = Wally.decodeBase58(wif, isCheck: true) else {
            return nil
        }
        
        if bytes.count == ECPrivateKey.keyLen + 1 {
            isPublicKeyCompressed = false
        } else if bytes.count == ECPrivateKey.keyLen + 2 && bytes.last! == 0x01 {
            isPublicKeyCompressed = true
            bytes.removeLast()
        } else {
            return nil
        }
        
        guard let network = Network.network(forWIFPrefix: bytes.first!) else {
            return nil
        }
        self.network = network
        bytes.removeFirst()
        
        guard let key = ECPrivateKey(bytes) else {
            return nil
        }
        self.key = key
    }

    public var description: String {
        Wally.encodeWIF(key: key.data, network: network, isPublicKeyCompressed: isPublicKeyCompressed)
    }
    
    public var taggedCBOR: CBOR {
        key.taggedCBOR
    }
}
