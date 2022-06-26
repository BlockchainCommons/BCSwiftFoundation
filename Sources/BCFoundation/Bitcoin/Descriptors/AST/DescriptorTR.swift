//
//  File.swift
//  
//
//  Created by Wolf McNally on 12/5/21.
//

import Foundation

// Currently implemented for single key only, and cannot yet output a ScriptPubKey.
struct DescriptorTR: DescriptorAST {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey? {
        fatalError("unimplemented")
    }
    
    func hdKey(chain: Chain?, addressIndex: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> HDKey? {
        key.hdKey(chain: chain, addressIndex: addressIndex, privateKeyProvider: privateKeyProvider)
    }

    var requiresAddressIndex: Bool {
        key.requiresAddressIndex
    }
    
    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST? {
        guard parser.parseKind(.tr) else {
            return nil
        }
        try parser.expectOpenParen()
        let key = try parser.expectKey()
        try parser.expectCloseParen()
        return DescriptorTR(key: key)
    }
    
    var unparsed: String {
        "tr(\(key))"
    }

    var untaggedCBOR: CBOR {
        key.taggedCBOR
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputTaproot, untaggedCBOR)
    }
}
