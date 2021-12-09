//
//  File.swift
//  
//
//  Created by Wolf McNally on 12/5/21.
//

import Foundation

// Currently implemented for single key only, and cannot yet output a ScriptPubKey.
struct DescriptorTR: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        fatalError("unimplemented")
    }
    
    var requiresWildcardChildNum: Bool {
        key.requiresWildcardChildNum
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.tr) else {
            return nil
        }
        try parser.expectOpenParen()
        let key = try parser.expectKey()
        try parser.expectCloseParen()
        return DescriptorTR(key: key)
    }
    
    var unparsed: String {
        "tr(\(key))"
    }

    var cbor: CBOR {
        key.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputTaproot, cbor)
    }
}
