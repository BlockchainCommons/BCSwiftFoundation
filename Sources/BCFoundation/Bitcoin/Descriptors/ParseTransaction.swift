//
//  ParseTransaction.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

protocol Parser {
    associatedtype Tokens
    
    var tokens: Tokens { get set }
}

final class ParseTransaction<P> where P: Parser {
    private var lexer: P
    private let save: P.Tokens
    private var isComitted = false
    
    init(_ parser: P) {
        self.lexer = parser
        save = parser.tokens
    }
    
    func commit() {
        isComitted = true
    }
    
    deinit {
        if !isComitted {
            lexer.tokens = save
        }
    }
}
