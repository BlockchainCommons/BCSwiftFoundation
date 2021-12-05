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
        
        guard let ok = orderedKeys(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        for orderedKey in ok {
            ops.append(.data(orderedKey))
        }
        ops.append(.op(ScriptOpcode(int: keys.count)!))
        ops.append(.op(.op_checkmultisig))
        return ScriptPubKey(Script(ops: ops))
    }
    
    func orderedKeys(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> [Data]? {
        let rawKeys = keys.compactMap { $0.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) }
        guard rawKeys.count == keys.count else {
            return nil
        }
        var orderedKeys = Array(zip(keys, rawKeys))
        if isSorted {
            orderedKeys.sort { $0.1.lexicographicallyPrecedes($1.1) }
        }
        return orderedKeys.map { $0.1 }
    }

    var requiresWildcardChildNum: Bool {
        keys.contains(where: { $0.requiresWildcardChildNum })
    }

    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        let isSorted: Bool
        if parser.parseKind(.multi) {
            isSorted = false
        } else if parser.parseKind(.sortedmulti) {
            isSorted = true
        } else {
            return nil
        }
        try parser.expectOpenParen()
        let threshold = try parser.expectInt()
        let keys = try parser.expectKeyList(allowUncompressed: false)
        try parser.expectCloseParen()
        return DescriptorMulti(threshold: threshold, keys: keys, isSorted: isSorted)
    }
    
    var unparsed: String {
        let keysString = keys.map({$0.description}).joined(separator: ",")
        let prefix = isSorted ? "sortedmulti" : "multi"
        return "\(prefix)(\(threshold),\(keysString))"
    }

    var cbor: CBOR {
        CBOR.orderedMap([
            .init(key: 1, value: .unsignedInt(UInt64(threshold))),
            .init(key: 2, value: .array(keys.map({ $0.taggedCBOR })))
        ])
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(isSorted ? .outputSortedMultisig : .outputMultisig, cbor)
    }
}
