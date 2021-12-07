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
        var a: [OrderedMapEntry] = [
            .init(key: 1, value: id.taggedCBOR)
        ]

        switch body {
        case .seed(let seed):
            a.append(.init(key: 2, value: seed.taggedCBOR))
        case .key(let key):
            a.append(.init(key: 2, value: key.taggedCBOR))
        case .psbtSignature(let psbt):
            a.append(.init(key: 2, value: psbt.taggedCBOR))
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
