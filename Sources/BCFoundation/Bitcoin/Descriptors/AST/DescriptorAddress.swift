//
//  DescriptorAddress.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorAddress: DescriptorAST {
    let address: Bitcoin.Address
    
    func scriptPubKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        address.scriptPubKey
    }
    
    func hdKey(keyType: KeyType, chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> HDKey? {
        nil
    }
    
    var baseKey: HDKey? {
        nil
    }
    
    func unparsedCompact(keys: inout [CBOR]) -> String {
        let cbor = address.cbor
        let index = keys.count
        keys.append(cbor)
        return "addr(@\(index))"
    }

    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.addr) else {
            return nil
        }
        try parser.expectOpenParen()
        let address = try parser.expectAddress()
        try parser.expectCloseParen()
        return DescriptorAddress(address: address)
    }
    
    var unparsed: String {
        "addr(\(address))"
    }
    
    var untaggedCBOR: CBOR {
        address.untaggedCBOR
    }
    
    var taggedCBOR: CBOR {
        address.taggedCBOR
    }
}
