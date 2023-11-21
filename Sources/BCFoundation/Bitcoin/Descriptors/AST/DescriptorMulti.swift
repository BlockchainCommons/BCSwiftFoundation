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
    
    func scriptPubKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        var ops: [ScriptOperation] = []
        ops.append(.op(ScriptOpcode(int: threshold)!))
        
        guard let ok = orderedKeys(chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        for orderedKey in ok {
            ops.append(.data(orderedKey))
        }
        ops.append(.op(ScriptOpcode(int: keys.count)!))
        ops.append(.op(.op_checkmultisig))
        return ScriptPubKey(Script(ops: ops))
    }
    
    func hdKey(keyType: KeyType, chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> HDKey? {
        nil
    }
    
    var baseKey: HDKey? {
        nil
    }

    func orderedKeys(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> [Data]? {
        let rawKeys = keys.compactMap { $0.pubKeyData(chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider) }
        guard rawKeys.count == keys.count else {
            return nil
        }
        var orderedKeys = Array(zip(keys, rawKeys))
        if isSorted {
            orderedKeys.sort { $0.1.lexicographicallyPrecedes($1.1) }
        }
        return orderedKeys.map { $0.1 }
    }

    var requiresAddressIndex: Bool {
        keys.contains(where: { $0.requiresAddressIndex })
    }
    
    var requiresChain: Bool {
        keys.contains(where: { $0.requiresChain })
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
    
    func unparsedCompact(keys: inout [CBOR]) -> String {
        var keyStrings: [String] = []
        for key in self.keys {
            if let cbor = key.compactCBOR {
                let index = keys.count
                keys.append(cbor)
                keyStrings.append("@\(index)")
            }
        }
        let keysString = keyStrings.map({$0}).joined(separator: ",")
        let prefix = isSorted ? "sortedmulti" : "multi"
        return "\(prefix)(\(threshold),\(keysString))"
    }

    var untaggedCBOR: CBOR {
        let map: DCBOR.Map = [
            1: threshold,
            2: keys.map { $0.taggedCBOR }
        ]
        return map.cbor
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(isSorted ? .outputSortedMultisig : .outputMultisig, untaggedCBOR)
    }
}
