//
//  SeedRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import CryptoSwift
@_exported import URKit

public struct SeedRequestBody {
    public let digest: Data
    
    public var cbor: CBOR {
        CBOR.byteString(digest.bytes)
    }
    
    public var taggedCBOR: CBOR {
        return CBOR.tagged(.seedRequestBody, cbor)
    }
    
    public init(digest: Data) throws {
        guard digest.count == SHA2.Variant.sha256.digestLength else {
            throw CBORError.invalidFormat
        }
        self.digest = digest
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.byteString(bytes) = cbor else {
            throw CBORError.invalidFormat
        }
        try self.init(digest: bytes.data)
    }
    
    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.seedRequestBody, cbor) = taggedCBOR else {
            return nil
        }
        try self.init(cbor: cbor)
    }
}
