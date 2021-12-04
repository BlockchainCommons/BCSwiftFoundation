//
//  DescriptorMulti.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorMulti: DescriptorAST {
    let threshold: Int
    let keys: [DescriptorKeyExpression]
    let isSorted: Bool
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        var ops: [ScriptOperation] = []
        ops.append(.op(ScriptOpcode(int: threshold)!))
        
        let rawKeys = keys.compactMap { $0.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) }
        guard rawKeys.count == keys.count else {
            return nil
        }
        var orderedKeys = Array(zip(keys, rawKeys))
        if isSorted {
            orderedKeys.sort { $0.1.lexicographicallyPrecedes($1.1) }
        }
        for orderedKey in orderedKeys {
            ops.append(.data(orderedKey.1))
        }
        ops.append(.op(ScriptOpcode(int: keys.count)!))
        ops.append(.op(.op_checkmultisig))
        return ScriptPubKey(Script(ops: ops))
    }

    var requiresWildcardChildNum: Bool {
        keys.contains(where: { $0.requiresWildcardChildNum })
    }
    
    var unparsed: String {
        let keysString = keys.map({$0.description}).joined(separator: ",")
        let prefix = isSorted ? "sortedmulti" : "multi"
        return "\(prefix)(\(threshold),\(keysString))"
    }
}
