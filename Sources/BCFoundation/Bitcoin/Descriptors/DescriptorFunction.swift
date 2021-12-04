//
//  DescriptorFunction.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

public protocol DescriptorFunction: CustomStringConvertible {
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey?
    var requiresWildcardChildNum: Bool { get }
    var unparsed: String { get }
//    var cbor: CBOR { get }
}

extension DescriptorFunction {
    public var requiresWildcardChildNum: Bool {
        false
    }
    
    public var description: String {
        unparsed
    }
}
