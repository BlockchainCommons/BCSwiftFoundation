//
//  OutputDescriptor.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation
@_exported import URKit

public struct OutputDescriptor {
    public let source: String
    private let astRoot: DescriptorAST
    
    public init(_ source: String) throws {
        self.source = source
        let tokens = try DescriptorLexer(source: source).lex()
        self.astRoot = try DescriptorParser(tokens: tokens, source: source).parse()
    }
    
    public func scriptPubKey(wildcardChildNum: UInt32? = nil, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> ScriptPubKey? {
        return astRoot.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
    }
    
    public var isCombo: Bool {
        return (astRoot as? DescriptorCombo) != nil
    }

    public enum ComboOutput {
        case pk
        case pkh
        case wpkh
        case sh_wpkh
    }
    
    public var requiresWildcardChildNum: Bool {
        astRoot.requiresWildcardChildNum
    }

    public var unparsed: String {
        astRoot.unparsed
    }
    
    public var cbor: CBOR {
        astRoot.taggedCBOR
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.output.tag, cbor)
    }
    
    public var ur: UR {
        return try! UR(type: URType.output.type, cbor: cbor)
    }
    
    public var checksum: String {
        Self.checksum(source)!
    }
    
    public var sourceWithChecksum: String {
        return "\(source)#\(checksum)"
    }
    
    public static func checksum(_ source: String) -> String? {
        descriptorChecksum(source)
    }
}

extension OutputDescriptor: CustomStringConvertible {
    public var description: String {
        source
    }
}
