//
//  DescriptorCombo.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorCombo: DescriptorAST {
    let key: DescriptorKeyExpression
    
    // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        guard let comboOutput = comboOutput else {
            return nil
        }
        switch comboOutput {
        case .pk:
            return DescriptorPK(key: key).scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: nil)
        case .pkh:
            return DescriptorPKH(key: key).scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: nil)
        case .wpkh:
            if case .ecUncompressedPublicKey = key.key {
                return nil
            }
            return DescriptorWPKH(key: key).scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: nil)
        case .sh_wpkh:
            if case .ecUncompressedPublicKey = key.key {
                return nil
            }
            let redeemScript = DescriptorWPKH(key: key)
            return DescriptorSH(redeemScript: redeemScript).scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: nil)
        }
    }

    var requiresWildcardChildNum: Bool {
        key.requiresWildcardChildNum
    }
    
    var unparsed: String {
        "combo(\(key))"
    }
}
