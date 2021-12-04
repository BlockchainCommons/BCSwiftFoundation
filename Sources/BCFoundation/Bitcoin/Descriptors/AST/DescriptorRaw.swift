//
//  DescriptorRaw.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorRaw: DescriptorAST {
    let data: Data
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        ScriptPubKey(Script(data))
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.raw) else {
            return nil
        }
        try parser.expectOpenParen()
        let data = try parser.expectData()
        try parser.expectCloseParen()
        return DescriptorRaw(data: data)
    }
    
    var unparsed: String {
        "raw(\(data.hex))"
    }
}
