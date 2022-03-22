//
//  TransactionResponse.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

public struct TransactionResponse {
    public let id: UUID
    public let body: Body
    
    public enum Body {
        case seed(SeedProtocol)
        case key(HDKeyProtocol)
        case psbtSignature(PSBT)
    }

    public init(id: UUID, body: Body) {
        self.id = id
        self.body = body
    }

    public var cbor: CBOR {
        var a: OrderedMap = [
            1: id.taggedCBOR
        ]

        switch body {
        case .seed(let seed):
            a.append(2, seed.taggedCBOR)
        case .key(let key):
            a.append(2, key.taggedCBOR)
        case .psbtSignature(let psbt):
            a.append(2, psbt.taggedCBOR)
        }
        
        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.transactionResponse.tag, cbor)
    }

    public var ur: UR {
        try! UR(type: URType.transactionResponse.type, cbor: cbor)
    }
}
