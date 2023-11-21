//
//  DescriptorSH.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorSH: DescriptorAST {
    let redeemScript: DescriptorAST
    
    func scriptPubKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        guard let redeemScript = redeemScript.scriptPubKey(chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_hash160), .data(redeemScript.script.data.hash160), .op(.op_equal)]))
    }
    
    func hdKey(keyType: KeyType, chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> HDKey? {
        redeemScript.hdKey(keyType: keyType, chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
    }
    
    var baseKey: HDKey? {
        redeemScript.baseKey
    }

    var requiresAddressIndex: Bool {
        redeemScript.requiresAddressIndex
    }
    
    var requiresChain: Bool {
        redeemScript.requiresChain
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
    
    func unparsedCompact(keys: inout [CBOR]) -> String {
        let content = redeemScript.unparsedCompact(keys: &keys)
        return "sh(\(content))"
    }

    var untaggedCBOR: CBOR {
        redeemScript.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputScriptHash, untaggedCBOR)
    }
}
