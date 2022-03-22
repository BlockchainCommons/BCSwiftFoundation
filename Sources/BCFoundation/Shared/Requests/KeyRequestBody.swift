//
//  KeyRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
@_exported import URKit

public struct KeyRequestBody {
    public let keyType: KeyType
    public let path: DerivationPath
    public let useInfo: UseInfo
    public let isDerivable: Bool
    
    public var cbor: CBOR {
        var a: OrderedMap = [
            1: .boolean(keyType.isPrivate),
            2: path.taggedCBOR
        ]
        
        if !useInfo.isDefault {
            a.append(3, useInfo.taggedCBOR)
        }
        
        if !isDerivable {
            a.append(4, .boolean(isDerivable))
        }
        
        return CBOR.orderedMap(a)
    }
    
    public var taggedCBOR: CBOR {
        return CBOR.tagged(.keyRequestBody, cbor)
    }

    public init(keyType: KeyType, path: DerivationPath, useInfo: UseInfo, isDerivable: Bool = true) {
        self.keyType = keyType
        self.path = path
        self.useInfo = useInfo
        self.isDerivable = isDerivable
    }

    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor else {
            throw CBORError.invalidFormat
        }
        guard let boolItem = pairs[1], case let CBOR.boolean(isPrivate) = boolItem else {
            // Key request doesn't contain isPrivate.
            throw CBORError.invalidFormat
        }
        guard let pathItem = pairs[2] else {
            // Key request doesn't contain derivation.
            throw CBORError.invalidFormat
        }
        let path = try DerivationPath(taggedCBOR: pathItem)
        
        let useInfo: UseInfo
        if let pathItem = pairs[3] {
            useInfo = try UseInfo(taggedCBOR: pathItem)
        } else {
            useInfo = UseInfo()
        }
        
        let isDerivable: Bool
        if let isDerivableItem = pairs[4] {
            guard case let CBOR.boolean(d) = isDerivableItem else {
                // Invalid isDerivable field
                throw CBORError.invalidFormat
            }
            isDerivable = d
        } else {
            isDerivable = true
        }
        
        self.init(keyType: KeyType(isPrivate: isPrivate), path: path, useInfo: useInfo, isDerivable: isDerivable)
    }

    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.keyRequestBody, cbor) = taggedCBOR else {
            return nil
        }
        try self.init(cbor: cbor)
    }
}
