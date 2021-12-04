//
//  DescriptorPK.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorPK: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.data(data), .op(.op_checksig)]))
    }
    
    var requiresWildcardChildNum: Bool {
        key.requiresWildcardChildNum
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.pk) else {
            return nil
        }
        try parser.expectOpenParen()
        let key = try parser.expectKey()
        try parser.expectCloseParen()
        return DescriptorPK(key: key)
    }
    
    var unparsed: String {
        "pk(\(key))"
    }
}
