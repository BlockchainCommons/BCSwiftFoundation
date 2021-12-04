//
//  DescriptorLexer.swift
//  BCFoundation
//
//  Created by Wolf McNally on 8/31/21.
//

import Foundation
import Flexer


final class DescriptorLexer: Parser {
    typealias Tokens = BasicTextCharacterLexer
    typealias Transaction = ParseTransaction<DescriptorLexer>
    typealias Error = DescriptorError<BasicTextCharacter>

    let source: String
    var tokens: Tokens
    
    init(source: String) {
        self.source = source
        self.tokens = Tokens(string: source)
    }

    func error(_ message: String) -> Error {
        Error(message, tokens.peek(), source: source)
    }
    
    func lex() throws -> [DescriptorToken] {
        var result: [DescriptorToken] = []
        while let t = try lexNext() {
            result.append(t)
        }
        return result
    }
    
    static func debugLex(_ source: String) throws -> String {
        let lexer = DescriptorLexer(source: source)
        let tokens = try lexer.lex()
        let strings = tokens.map { lexer.summary(of: $0) }
        return strings.joined(separator: ", ")
    }
    
    func summary(of token: DescriptorToken) -> String {
        "(\(token.kind) \(range(of: token)))"
    }
    
    func range(of token: DescriptorToken) -> Range<Int> {
        let a = source.distance(from: source.startIndex, to: token.startIndex)
        let b = source.distance(from: source.startIndex, to: token.endIndex)
        return a ..< b
    }

    func lexNext() throws -> DescriptorToken? {
        guard tokens.peek() != nil else {
            return nil
        }
        
        let tokenLexers = [
            lexDelimiters,
            lexKeywords,
            lexAddress,
            lexWIF,
            lexHDKey,
            lexData,
            lexInt,
            lexHardened
        ]

        for tokenLexer in tokenLexers {
            if let token = tokenLexer() {
                return token
            }
        }
        
        throw error("Unrecognized token.")
    }

    static let delimiters: [(BasicTextCharacterKind, DescriptorToken.Kind)] = [
        (.openParen, .openParen),
        (.closeParen, .closeParen),
        (.openBracket, .openBracket),
        (.closeBracket, .closeBracket),
        (.openBrace, .openBrace),
        (.closeBrace, .closeBrace),
        (.comma, .comma),
        (.slash, .slash),
        (.star, .star)
    ]
    
    func lexDelimiters() -> DescriptorToken? {
        func lexDelimiter(kind: BasicTextCharacterKind, descriptorKind: DescriptorToken.Kind) -> DescriptorToken? {
            let transaction = Transaction(self)
            
            guard
                let token = tokens.peek(),
                token.kind == kind,
                let endingToken = tokens.next() else
            {
                return nil
            }
            let range = token.startIndex ..< endingToken.endIndex
            transaction.commit()
            return DescriptorToken(kind: descriptorKind, range: range)
        }

        for delimiter in Self.delimiters {
            if let descriptorToken = lexDelimiter(kind: delimiter.0, descriptorKind: delimiter.1) {
                return descriptorToken
            }
        }
        return nil
    }

    static let keywords: [(String, DescriptorToken.Kind)] = [
        ("sh", .sh),
        ("wsh", .wsh),
        ("pk", .pk),
        ("pkh", .pkh),
        ("wpkh", .wpkh),
        ("combo", .combo),
        ("multi", .multi),
        ("sortedmulti", .sortedmulti),
        ("tr", .tr),
        ("addr", .addr),
        ("raw", .raw)
    ]
    
    func lexKeywords() -> DescriptorToken? {
        func lexKeyword(keyword: String, kind: DescriptorToken.Kind) -> DescriptorToken? {
            let transaction = Transaction(self)

            guard
                let token = tokens.peek(),
                token.kind == .lowercaseLetter,
                let endingToken = tokens.nextUntil(notIn: [.lowercaseLetter])
            else {
                return nil
            }
            let range = token.startIndex ..< endingToken.endIndex
            guard source[range] == keyword else {
                return nil
            }
            transaction.commit()
            return DescriptorToken(kind: kind, range: range)
        }

        for keyword in Self.keywords {
            if let descriptorToken = lexKeyword(keyword: keyword.0, kind: keyword.1) {
                return descriptorToken
            }
        }
        return nil
    }
    
    func character(of token: BasicTextCharacter) -> Character {
        source[token.range].first!
    }
    
    func substring(of range: Range<Token<BasicTextCharacterKind>.Index>) -> String {
        String(source[range])
    }
    
    func isHexDigit(token: BasicTextCharacter) -> Bool {
        CharacterSet.hexDigits.contains(character(of: token))
    }
    
    func isBase58(token: BasicTextCharacter) -> Bool {
        CharacterSet.base58.contains(character(of: token))
    }
    
    func isAllowedInAddress(token: BasicTextCharacter) -> Bool {
        CharacterSet.allowedInAddress.contains(character(of: token))
    }
    
    func lexData() -> DescriptorToken? {
        let transaction = Transaction(self)

        guard
            let token = tokens.peek(),
            isHexDigit(token: token),
            let endingToken = tokens.nextUntil( { !isHexDigit(token: $0) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard
            let data = Data(hex: substring(of: range)),
            data.count > 1 // reject short data as it's probably an int
        else {
            return nil
        }
        transaction.commit()
        return DescriptorToken(kind: .data, range: range, payload: data)
    }
    
    func lexAddress() -> DescriptorToken? {
        let transaction = Transaction(self)

        guard
            let token = tokens.peek(),
            isAllowedInAddress(token: token),
            let endingToken = tokens.nextUntil( { !isAllowedInAddress(token: $0) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let address = Bitcoin.Address(string: substring(of: range)) else {
            return nil
        }
        transaction.commit()
        return DescriptorToken(kind: .address, range: range, payload: address)
    }
    
    func lexWIF() -> DescriptorToken? {
        let transaction = Transaction(self)

        guard
            let token = tokens.peek(),
            isBase58(token: token),
            let endingToken = tokens.nextUntil( { !isBase58(token: $0) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let wif = WIF(substring(of: range)) else {
            return nil
        }
        transaction.commit()
        return DescriptorToken(kind: .wif, range: range, payload: wif)
    }

    func lexHDKey() -> DescriptorToken? {
        let transaction = Transaction(self)

        guard
            let token = tokens.peek(),
            isBase58(token: token),
            let endingToken = tokens.nextUntil( { !isBase58(token: $0) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let hdKey = try? HDKey(base58: substring(of: range)) else {
            return nil
        }
        transaction.commit()
        return DescriptorToken(kind: .hdKey, range: range, payload: hdKey)
    }
    
    func lexInt() -> DescriptorToken? {
        let transaction = Transaction(self)

        guard
            let token = tokens.peek(),
            token.kind == .digit,
            let endingToken = tokens.nextUntil(notIn: [.digit])
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let value = Int(substring(of: range)) else {
            return nil
        }
        
        transaction.commit()
        return DescriptorToken(kind: .int, range: range, payload: value)
    }
    
    func lexHardened() -> DescriptorToken? {
        let transaction = Transaction(self)

        guard
            let token = tokens.peek(),
            "'h".contains(character(of: token)),
            let endingToken = tokens.next()
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        
        transaction.commit()
        return DescriptorToken(kind: .isHardened, range: range)
    }
}
