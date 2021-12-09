//
//  DescriptorWSH.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorWSH: DescriptorAST {
    let redeemScript: DescriptorAST
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        guard let redeemScript = redeemScript.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_0), .data(redeemScript.script.data.sha256Digest)]))
    }

    var requiresWildcardChildNum: Bool {
        redeemScript.requiresWildcardChildNum
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.wsh) else {
            return nil
        }
        let redeemScript: DescriptorAST
        try parser.expectOpenParen()
        if let pk = try DescriptorPK.parse(parser) {
            redeemScript = pk
        } else if let pkh = try DescriptorPKH.parse(parser) {
            redeemScript = pkh
        } else if let multi = try DescriptorMulti.parse(parser) {
            redeemScript = multi
        } else if let cosigner = try DescriptorCosigner.parse(parser) {
            redeemScript = cosigner
        } else {
            throw parser.error("wsh() expected one of: pk(), pkh(), multi(), sortedmulti(), cosigner().")
        }
        try parser.expectCloseParen()
        return DescriptorWSH(redeemScript: redeemScript)
    }
    
    var unparsed: String {
        "wsh(\(redeemScript))"
    }

    var cbor: CBOR {
        redeemScript.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputWitnessScriptHash, cbor)
    }
}
