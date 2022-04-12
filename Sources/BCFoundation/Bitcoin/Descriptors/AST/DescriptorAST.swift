//
//  DescriptorAST.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation
@_exported import URKit

protocol DescriptorAST: CustomStringConvertible {
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: OutputDescriptor.ComboOutput?) -> ScriptPubKey?
    var requiresWildcardChildNum: Bool { get }
    var unparsed: String { get }
    var untaggedCBOR: CBOR { get }
    var taggedCBOR: CBOR { get }

    static func parse(_ parser: DescriptorParser) throws -> DescriptorAST?
}

extension DescriptorAST {
    var requiresWildcardChildNum: Bool {
        false
    }
    
    var description: String {
        unparsed
    }
}
