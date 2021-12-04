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
    
    var unparsed: String {
        "raw(\(data.hex))"
    }
}
