//
//  File.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

public struct PSBTSignatureRequestBody {
    public let psbt: PSBT
    public let isRawPSBT: Bool
    
    public init(psbt: PSBT, isRawPSBT: Bool = false) {
        self.psbt = psbt
        self.isRawPSBT = isRawPSBT
    }
    
    public var cbor: CBOR {
        var a: [OrderedMapEntry] = []
        a.append(.init(key: 1, value: psbt.taggedCBOR))
        return CBOR.orderedMap(a)
    }

    public var taggedCBOR: CBOR {
        return CBOR.tagged(.psbtSignatureRequestBody, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor else {
            throw Error.invalidFormat
        }
        guard let taggedCBORItem = pairs[1] else {
            // PSBT signing request doesn't contain PSBT data.
            throw Error.invalidFormat
        }
        try self.init(psbt: PSBT(taggedCBOR: taggedCBORItem))
    }
    
    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.psbtSignatureRequestBody, cbor) = taggedCBOR else {
            return nil
        }
        try self.init(cbor: cbor)
    }

    public enum Error: Swift.Error {
        case invalidFormat
    }
}
