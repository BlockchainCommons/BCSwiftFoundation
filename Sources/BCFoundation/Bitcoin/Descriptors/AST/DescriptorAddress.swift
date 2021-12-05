//
//  DescriptorAddress.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

struct DescriptorAddress: DescriptorAST {
    let address: Bitcoin.Address
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey? {
        address.scriptPubKey
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
    
    var cbor: CBOR {
        address.cbor
    }
    
    var taggedCBOR: CBOR {
        address.taggedCBOR
    }
}
