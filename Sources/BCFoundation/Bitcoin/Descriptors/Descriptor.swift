//
//  Descriptor.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation
@_exported import URKit

public struct Descriptor {
    public let source: String
    public let function: DescriptorFunction
    
    public init(_ source: String) throws {
        self.source = source
        let tokens = try DescriptorLexer(source: source).lex()
        self.function = try DescriptorParser(tokens: tokens, source: source).parse()
    }
    
    public func scriptPubKey(wildcardChildNum: UInt32? = nil, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> ScriptPubKey? {
        return function.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
    }
    
    public var isCombo: Bool {
        return (function as? DescriptorCombo) != nil
    }

    public enum ComboOutput {
        case pk
        case pkh
        case wpkh
        case sh_wpkh
    }
    
    public var requiresWildcardChildNum: Bool {
        function.requiresWildcardChildNum
    }

    public var unparsed: String {
        function.unparsed
    }
}

extension Descriptor: CustomStringConvertible {
    public var description: String {
        source
    }
}
