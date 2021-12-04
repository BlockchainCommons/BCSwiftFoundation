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
    private let ast: DescriptorAST
    
    public init(_ source: String) throws {
        self.source = source
        let tokens = try DescriptorLexer(source: source).lex()
        self.ast = try DescriptorParser(tokens: tokens, source: source).parse()
    }
    
    public func scriptPubKey(wildcardChildNum: UInt32? = nil, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> ScriptPubKey? {
        return ast.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
    }
    
    public var isCombo: Bool {
        return (ast as? DescriptorCombo) != nil
    }

    public enum ComboOutput {
        case pk
        case pkh
        case wpkh
        case sh_wpkh
    }
    
    public var requiresWildcardChildNum: Bool {
        ast.requiresWildcardChildNum
    }

    public var unparsed: String {
        ast.unparsed
    }
    
    public var cbor: CBOR {
        ast.cbor
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.output, cbor)
    }
}

extension Descriptor: CustomStringConvertible {
    public var description: String {
        source
    }
}
