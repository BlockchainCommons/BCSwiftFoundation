//
//  DescriptorRaw.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorRaw: DescriptorAST {
    let script: Script
    
    func scriptPubKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        ScriptPubKey(script)
    }
    
    func hdKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> HDKey? {
        nil
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
    
    var untaggedCBOR: CBOR {
        CBOR.data(script.data)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputRawScript, untaggedCBOR)
    }
}
