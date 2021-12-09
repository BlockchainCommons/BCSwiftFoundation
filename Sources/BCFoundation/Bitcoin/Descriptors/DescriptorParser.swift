//
//  DescriptorLexer.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
import Flexer
import WolfBase
@_exported import BCWally

final class DescriptorParser: Parser {
    typealias Tokens = LookAheadSequence<[DescriptorToken]>
    typealias Transaction = ParseTransaction<DescriptorParser>
    typealias Error = OutputDescriptorError<DescriptorToken>

    let source: String
    var tokens: Tokens
    
    init(tokens: [DescriptorToken], source: String) {
        self.tokens = tokens.lookAhead
        self.source = source
    }
    
    func error(_ message: String) -> Error {
        Error(message, tokens.peek(), source: source)
    }
    
    static let topLevelTypes: [DescriptorAST.Type] = [
        DescriptorRaw.self,
        DescriptorPK.self,
        DescriptorPKH.self,
        DescriptorWPKH.self,
        DescriptorMulti.self,
        DescriptorWSH.self,
        DescriptorSH.self,
        DescriptorTR.self,
        DescriptorAddress.self,
        DescriptorCombo.self,
        DescriptorCosigner.self
    ]
    
    func parse() throws -> DescriptorAST {
        for type in Self.topLevelTypes {
            if let raw = try type.parse(self) {
                return raw
            }
        }
        throw error("Descriptor: expected top-level script function.")
    }
}

extension DescriptorParser {
    func parseFingerprint() -> UInt32? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data,
            token.data.count == 4
        else {
            return nil
        }
        transaction.commit()
        return deserialize(UInt32.self, token.data)
    }
    
    func expectFingerprint() throws -> UInt32 {
        guard let fingerprint = parseFingerprint() else {
            throw error("Fingerprint expected.")
        }
        return fingerprint
    }
    
    func parseSlash() -> Bool {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .slash
        else {
            return false
        }
        transaction.commit()
        return true
    }
    
    func parseToken(kind: DescriptorToken.Kind) -> DescriptorToken? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == kind
        else {
            return nil
        }
        transaction.commit()
        return token
    }

    func parseKind(_ kind: DescriptorToken.Kind) -> Bool {
        parseToken(kind: kind) != nil
    }
    
    func parseInt() -> Int? {
        let transaction = Transaction(self)
        guard let token = tokens.next() else {
            return nil
        }
        if token.kind == .int {
            let i = token.int
            transaction.commit()
            return i
        } else if token.kind == .data {
            guard let i = Int(token.data.hex) else {
                return nil
            }
            transaction.commit()
            return i
        } else {
            return nil
        }
    }
    
    func expectInt() throws -> Int {
        guard let i = parseInt() else {
            throw error("Expected integer.")
        }
        return i
    }

    func parseChildnum() -> ChildIndex? {
        let transaction = Transaction(self)
        guard
            let i = parseInt(),
            (0 ..< Int(BIP32_INITIAL_HARDENED_CHILD)).contains(i)
        else {
            return nil
        }
        transaction.commit()
        return ChildIndex(UInt32(i))
    }

    func parseWildcard() -> Bool {
        parseKind(.star)
    }

    func parseOpenParen() -> Bool {
        parseKind(.openParen)
    }
    
    func expectOpenParen() throws {
        guard parseOpenParen() else {
            throw error("Expected open parenthesis.")
        }
    }

    func parseCloseParen() -> Bool {
        parseKind(.closeParen)
    }
    
    func expectCloseParen() throws {
        guard parseCloseParen() else {
            throw error("Expected close parenthesis.")
        }
    }

    func parseOpenBracket() -> Bool {
        parseKind(.openBracket)
    }

    func parseCloseBracket() -> Bool {
        parseKind(.closeBracket)
    }
    
    func expectCloseBracket() throws {
        guard parseCloseBracket() else {
            throw error("Expected close bracket.")
        }
    }
    
    func parseComma() -> Bool {
        parseKind(.comma)
    }
    
    func expectComma() throws {
        guard parseComma() else {
            throw error("Expected comma.")
        }
    }

    func parseIndex() -> ChildIndexSpec? {
        if parseWildcard() {
            return .indexWildcard
        }
        if let childNum = parseChildnum() {
            return .index(childNum)
        }
        return nil
    }
    
    func expectIndex() throws -> ChildIndexSpec {
        guard let index = parseIndex() else {
            throw error("Expected index.")
        }
        return index
    }
    
    func parseIsHardened() -> Bool {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .isHardened
        else {
            return false
        }
        transaction.commit()
        return true
    }
    
    func parseDerivationStep() throws -> DerivationStep? {
        guard parseSlash() else {
            return nil
        }
        let index = try expectIndex()
        let isHardened = parseIsHardened()
        return DerivationStep(index, isHardened: isHardened)
    }
    
    func parseDerivationSteps(allowFinalWildcard: Bool) throws -> [DerivationStep] {
        var steps: [DerivationStep] = []
        while let step = try parseDerivationStep() {
            steps.append(step)
        }
        if !steps.isEmpty {
            guard steps.dropLast().allSatisfy({ $0.childIndexSpec != .indexWildcard }) else {
                if allowFinalWildcard {
                    throw error("Wildcard not allowed except on last step.")
                } else {
                    throw error("Wildcard not allowed.")
                }
            }
            if !allowFinalWildcard {
                guard steps.last!.childIndexSpec != .indexWildcard else {
                    throw error("Wildcard not allowed.")
                }
            }
        }
        return steps
    }
    
    func parseOrigin() throws -> DerivationPath? {
        guard parseOpenBracket() else {
            return nil
        }
        let fingerprint = try expectFingerprint()
        let steps = try parseDerivationSteps(allowFinalWildcard: false)
        try expectCloseBracket()
        return DerivationPath(steps: steps, origin: .fingerprint(fingerprint))
    }
    
    func parseChildren() throws -> DerivationPath? {
        let childSteps = try parseDerivationSteps(allowFinalWildcard: true)
        guard !childSteps.isEmpty else {
            return nil
        }
        return DerivationPath(steps: childSteps)
    }
    
    func parseData() -> Data? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data
        else {
            return nil
        }
        transaction.commit()
        return token.data
    }
    
    func expectData() throws -> Data {
        guard let data = parseData() else {
            throw error("Expected data.")
        }
        return data
    }

    func parseKey(allowUncompressed: Bool = true) throws -> DescriptorKeyExpression? {
        let transaction = Transaction(self)

        let origin = try parseOrigin()
        
        guard
            let token = tokens.next()
        else {
            return nil
        }
        let resultKey: DescriptorKeyExpression.Key?
        switch token.kind {
        case .data:
            let data = token.data
            if
                data.count == ECCompressedPublicKey.keyLen,
                [0x02, 0x03].contains(data[0])
            {
                resultKey = .ecCompressedPublicKey(ECCompressedPublicKey(data)!)
            } else if
                allowUncompressed,
                data.count == ECUncompressedPublicKey.keyLen
            {
                resultKey = .ecUncompressedPublicKey(ECUncompressedPublicKey(data)!)
            // } else if data.count == ECXOnlyPublicKey.keyLen {
            //     resultKey = .ecXOnlyPublicKey(ECXOnlyPublicKey(data)!)
            } else {
                resultKey = nil
            }
        case .wif:
            resultKey = .wif(token.wif)
        case .hdKey:
            let key = token.hdKey
            let children = try parseChildren()
            let key2 = try HDKey(key: key, parent: origin, children: children)
            resultKey = .hdKey(key2)
        default:
            resultKey = nil
        }

        guard let result = resultKey else {
            return nil
        }
        
        transaction.commit()
        return DescriptorKeyExpression(origin: origin, key: result)
    }
    
    func expectKey(allowUncompressed: Bool = true) throws -> DescriptorKeyExpression {
        guard let key = try parseKey(allowUncompressed: allowUncompressed) else {
            throw error("Expected key expression.")
        }
        return key
    }
    
    func expectKeyList(allowUncompressed: Bool = true) throws -> [DescriptorKeyExpression] {
        let transaction = Transaction(self)
        var result: [DescriptorKeyExpression] = []
        while parseComma() {
            try result.append(expectKey(allowUncompressed: allowUncompressed))
        }
        guard !result.isEmpty else {
            throw error("Expected list of keys.")
        }
        transaction.commit()
        return result
    }
    
    func parseAddress() -> Bitcoin.Address? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .address
        else {
            return nil
        }
        transaction.commit()
        return token.address
    }

    func expectAddress() throws -> Bitcoin.Address {
        guard let address = parseAddress() else {
            throw error("Expected address.")
        }
        return address
    }
    
    func parseScript() -> Script? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data
        else {
            return nil
        }
        let script = Script(token.data)
        guard script.operations != nil else {
            return nil
        }
        transaction.commit()
        return script
    }
    
    func expectScript() throws -> Script {
        guard let script = parseScript() else {
            throw error("Expected script.")
        }
        return script
    }
}
