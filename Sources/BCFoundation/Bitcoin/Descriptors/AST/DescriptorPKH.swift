//
//  DescriptorPKH.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorPKH: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_dup), .op(.op_hash160), .data(data.hash160), .op(.op_equalverify), .op(.op_checksig)]))
    }

    var requiresWildcardChildNum: Bool {
        key.requiresWildcardChildNum
    }
    
    var unparsed: String {
        "pkh(\(key))"
    }
}
