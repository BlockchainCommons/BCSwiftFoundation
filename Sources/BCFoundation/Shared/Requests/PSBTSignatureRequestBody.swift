//
//  PSBTSignatureRequestBody.swift
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
    
    public var untaggedCBOR: CBOR {
        CBOR.orderedMap([1: psbt.taggedCBOR])
    }

    public var taggedCBOR: CBOR {
        return CBOR.tagged(.psbtSignatureRequestBody, untaggedCBOR)
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor else {
            throw CBORError.invalidFormat
        }
        guard let taggedCBORItem = pairs[1] else {
            // PSBT signing request doesn't contain PSBT data.
            throw CBORError.invalidFormat
        }
        try self.init(psbt: PSBT(taggedCBOR: taggedCBORItem))
    }
    
    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.psbtSignatureRequestBody, cbor) = taggedCBOR else {
            return nil
        }
        try self.init(cbor: cbor)
    }
}
