//
//  OutputDescriptor.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation
@_exported import URKit
import WolfBase
import Flexer

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
    
    public var untaggedCBOR: CBOR {
        astRoot.taggedCBOR
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.output.tag, untaggedCBOR)
    }
    
    public var ur: UR {
        return try! UR(type: URType.output.type, cbor: untaggedCBOR)
    }
}

extension OutputDescriptor: CustomStringConvertible {
    public var description: String {
        source
    }
}

extension OutputDescriptor {
    public var checksum: String {
        Self.checksum(source)!
    }
    
    public var sourceWithChecksum: String {
        return "\(source)#\(checksum)"
    }
    
    public static func checksum(_ source: String) -> String? {
        descriptorChecksum(source)
    }
    
    public static func extractChecksum(_ source: String) -> (String, String?, StringRange?) {
        let regex = try! ~/".*#(.*)$"
        let matches = regex ~?? source
        if matches.isEmpty {
            return (source, nil, nil)
        }
        let range = matches[0].stringRange(in: source, at: 1)
        let checksum = String(source[range])
        let strippedSource = String(source.dropLast(checksum.count + 1))
        return (strippedSource, checksum, range)
    }
    
    public static func validateChecksum(_ source: String) throws {
        let (strippedSource, checksum, range) = extractChecksum(source)
        if
            let checksum = checksum,
            let range = range
        {
            guard checksum == Self.checksum(strippedSource) else {
                let token = DescriptorToken(kind: .checksum, range: range)
                throw OutputDescriptorError("Invalid checksum.", token, source: source)
            }
        }
    }
}

extension OutputDescriptor {
    public func address(useInfo: UseInfo, wildcardChildNum: UInt32? = nil, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> Bitcoin.Address? {
        guard let scriptPubKey = self.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput) else {
            return nil
        }
        return Bitcoin.Address(scriptPubKey: scriptPubKey, useInfo: useInfo)
    }
    
    public func addresses(useInfo: UseInfo, indexes: IndexSet, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> [UInt32: Bitcoin.Address] {
        var result: [UInt32: Bitcoin.Address] = [:]
        for index in indexes.lazy.map({ UInt32($0) }) {
            result[index] = address(useInfo: useInfo, wildcardChildNum: index, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
        }
        return result
    }
    
    public func addresses(useInfo: UseInfo, indexes: Range<UInt32>, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> [UInt32: Bitcoin.Address] {
        let indexes = IndexSet(Int(indexes.startIndex)..<Int(indexes.endIndex))
        return addresses(useInfo: useInfo, indexes: indexes, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
    }
}
