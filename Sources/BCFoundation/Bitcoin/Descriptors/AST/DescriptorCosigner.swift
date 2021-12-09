//
//  DescriptorCosigner.swift
//  
//
//  Created by Wolf McNally on 12/6/21.
//

import Foundation

struct DescriptorCosigner: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        return nil
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.cosigner) else {
            return nil
        }
        try parser.expectOpenParen()
        let key = try parser.expectKey()
        try parser.expectCloseParen()
        return DescriptorCosigner(key: key)
    }
    
    var unparsed: String {
        "cosigner(\(key))"
    }

    var cbor: CBOR {
        key.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputCosigner, cbor)
    }
}
