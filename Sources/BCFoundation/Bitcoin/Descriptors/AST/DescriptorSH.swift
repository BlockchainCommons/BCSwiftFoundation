//
//  DescriptorSH.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorSH: DescriptorAST {
    let redeemScript: DescriptorAST
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        guard let redeemScript = redeemScript.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_hash160), .data(redeemScript.script.data.hash160), .op(.op_equal)]))
    }

    var requiresWildcardChildNum: Bool {
        redeemScript.requiresWildcardChildNum
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.sh) else {
            return nil
        }
        let redeemScript: DescriptorAST
        try parser.expectOpenParen()
        if let pk = try DescriptorPK.parse(parser) {
            redeemScript = pk
        } else if let pkh = try DescriptorPKH.parse(parser) {
            redeemScript = pkh
        } else if let wpkh = try DescriptorWPKH.parse(parser) {
            redeemScript = wpkh
        } else if let wsh = try DescriptorWSH.parse(parser) {
            redeemScript = wsh
        } else if let multi = try DescriptorMulti.parse(parser) {
            redeemScript = multi
        } else if let cosigner = try DescriptorCosigner.parse(parser) {
            redeemScript = cosigner
        } else {
            throw parser.error("wsh() expected one of: pk(), pkh(), wpkh(), wsh(), multi(), sortedmulti(), cosigner().")
        }
        try parser.expectCloseParen()
        return DescriptorSH(redeemScript: redeemScript)
    }
    
    var unparsed: String {
        "sh(\(redeemScript))"
    }

    var cbor: CBOR {
        redeemScript.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputScriptHash, cbor)
    }
}
