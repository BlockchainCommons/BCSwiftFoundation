//
//  File.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorWPKH: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_0), .data(data.hash160)]))
    }
    
    func hdKey(keyType: KeyType, chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> HDKey? {
        key.hdKey(keyType: keyType, chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider)
    }
    
    var baseKey: HDKey? {
        key.baseKey
    }

    var requiresAddressIndex: Bool {
        key.requiresAddressIndex
    }
    
    var requiresChain: Bool {
        key.requiresChain
    }

    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.wpkh) else {
            return nil
        }
        try parser.expectOpenParen()
        let key = try parser.expectKey()
        try parser.expectCloseParen()
        return DescriptorWPKH(key: key)
    }
    
    var unparsed: String {
        "wpkh(\(key))"
    }
    
    func unparsedCompact(keys: inout [CBOR]) -> String {
        if let cbor = key.compactCBOR {
            let index = keys.count
            keys.append(cbor)
            return "wpkh(@\(index))"
        } else {
            return unparsed
        }
    }

    var untaggedCBOR: CBOR {
        key.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputWitnessPublicKeyHash, untaggedCBOR)
    }
}
