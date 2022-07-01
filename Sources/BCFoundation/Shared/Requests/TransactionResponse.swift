//
//  TransactionResponse.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

public enum TransactionResponseError: Swift.Error {
    case unknownResponseType
}

public struct TransactionResponse {
    public let id: UUID
    public let body: Body
    
    public enum Body {
        case seed(SeedProtocol)
        case key(HDKeyProtocol)
        case psbtSignature(PSBT)
        case outputDescriptor(OutputDescriptorResponseBody)
    }

    public init(id: UUID, body: Body) {
        self.id = id
        self.body = body
    }

    public var untaggedCBOR: CBOR {
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
        case .outputDescriptor(let descriptorResponse):
            a.append(2, descriptorResponse.taggedCBOR)
        }
        
        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.transactionResponse.tag, untaggedCBOR)
    }

    public var ur: UR {
        try! UR(type: URType.transactionResponse.type, cbor: untaggedCBOR)
    }
    
    public init(cborData: Data) throws {
        let cbor = try CBOR(cborData)
        try self.init(untaggedCBOR: cbor)
    }
    
    public init(ur: UR) throws {
        guard ur.type == URType.transactionResponse.type else {
            throw URError.unexpectedType
        }
        try self.init(cborData: ur.cbor)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.map(pairs) = untaggedCBOR,
            let idItem = pairs[1],
            let id = try? UUID(taggedCBOR: idItem),
            let bodyItem = pairs[2]
        else {
            throw CBORError.invalidFormat
        }
        
        let body: Body
        
        if let seed = try? Seed(taggedCBOR: bodyItem) {
            body = Body.seed(seed)
        } else if let key = try? HDKey(taggedCBOR: bodyItem) {
            body = Body.key(key)
        } else if let psbt = try? PSBT(taggedCBOR: bodyItem) {
            body = Body.psbtSignature(psbt)
        } else if let outputDescriptorResponseBody = try? OutputDescriptorResponseBody(taggedCBOR: bodyItem) {
            body = Body.outputDescriptor(outputDescriptorResponseBody)
        } else {
            throw TransactionResponseError.unknownResponseType
        }
        
        self.id = id
        self.body = body
    }
}
