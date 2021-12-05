//
//  DescriptorRaw.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorRaw: DescriptorAST {
    let script: Script
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        ScriptPubKey(script)
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.raw) else {
            return nil
        }
        try parser.expectOpenParen()
        let data = try parser.expectData()
        try parser.expectCloseParen()
        return DescriptorRaw(script: Script(data))
    }
    
    var unparsed: String {
        "raw(\(script.hex))"
    }
    
    var cbor: CBOR {
        CBOR.data(script.data)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputRawScript, cbor)
    }
}
