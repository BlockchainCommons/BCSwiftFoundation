//
//  OutputDescriptorError.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation
import Flexer

public struct OutputDescriptorError<T>: Error, CustomStringConvertible where T: TokenProtocol, T.Index == String.Index {
    public let message: String
    let token: String?
    public let source: String
    
    init(_ message: String, _ token: T?, source: String) {
        self.message = message
        self.token = token?.description
        self.source = source
    }
    
    private var range: Range<Int> {
        guard let token = token else {
            return source.count ..< source.count
        }
        let a = source.distance(from: source.startIndex, to: token.startIndex)
        let b = source.distance(from: source.startIndex, to: token.endIndex)
        return a ..< b
    }

    public var description: String {
        "\(message): \(range)"
    }
}
