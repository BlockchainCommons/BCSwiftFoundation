//
//  UUIDExtensions.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

extension UUID {
    public var untaggedCBOR: CBOR {
        CBOR.data(serialized)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.uuid, untaggedCBOR)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.data(bytes) = cbor,
            bytes.count == MemoryLayout<uuid_t>.size
        else {
            throw CBORError.invalidFormat
        }
        self = bytes.withUnsafeBytes {
            UUID(uuid: $0.bindMemory(to: uuid_t.self).baseAddress!.pointee)
        }
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.uuid, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
}
