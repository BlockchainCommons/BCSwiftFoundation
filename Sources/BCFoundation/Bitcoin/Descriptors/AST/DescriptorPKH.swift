//
//  DescriptorPKH.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorPKH: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_dup), .op(.op_hash160), .data(data.hash160), .op(.op_equalverify), .op(.op_checksig)]))
    }

    var requiresWildcardChildNum: Bool {
        key.requiresWildcardChildNum
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.pkh) else {
            return nil
        }
        try parser.expectOpenParen()
        let key = try parser.expectKey()
        try parser.expectCloseParen()
        return DescriptorPKH(key: key)
    }
    
    var unparsed: String {
        "pkh(\(key))"
    }

    var cbor: CBOR {
        key.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputPublicKeyHash, cbor)
    }
}
