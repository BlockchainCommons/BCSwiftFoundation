//
//  PSBTSignatureRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit

public struct PSBTSignatureRequestBody {
    public let psbt: PSBT
    public let isRawPSBT: Bool
    
    public init(psbt: PSBT, isRawPSBT: Bool = false) {
        self.psbt = psbt
        self.isRawPSBT = isRawPSBT
    }
}

public extension PSBTSignatureRequestBody {
    var untaggedCBOR: CBOR {
        CBOR.orderedMap([1: psbt.taggedCBOR])
    }

    var taggedCBOR: CBOR {
        return CBOR.tagged(.psbtSignatureRequestBody, untaggedCBOR)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard case let CBOR.map(pairs) = untaggedCBOR else {
            throw CBORError.invalidFormat
        }
        guard let taggedCBORItem = pairs[1] else {
            // PSBT signing request doesn't contain PSBT data.
            throw CBORError.invalidFormat
        }
        try self.init(psbt: PSBT(taggedCBOR: taggedCBORItem))
    }
    
    init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.psbtSignatureRequestBody, untaggedCBOR) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

public extension PSBTSignatureRequestBody {
    var envelope: Envelope {
        Envelope(function: .signPSBT)
            .add(.parameter(.psbt, value: psbt))
    }
}
