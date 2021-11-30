//
//  FlexerExtensions.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/5/21.
//

import Foundation
import Flexer

extension LookAheadIteratorProtocol {
    mutating func next(count: Int) -> [Element]? {
        var result: [Element] = []
        for _ in 0..<count {
            guard let elem = next() else {
                return nil
            }
            result.append(elem)
        }
        return result
    }
}
