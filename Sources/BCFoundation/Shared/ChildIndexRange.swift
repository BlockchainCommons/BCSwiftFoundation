//
//  ChildIndexRange.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation

public struct ChildIndexRange: Equatable {
    public let low: ChildIndex
    public let high: ChildIndex
    public init?(low: ChildIndex, high: ChildIndex) {
        guard low < high else {
            return nil
        }
        self.low = low
        self.high = high
    }
}

extension ChildIndexRange: CustomStringConvertible {
    public var description: String {
        "\(low)-\(high)"
    }
}

extension ChildIndexRange {
    public static func parse(_ s: String) -> ChildIndexRange? {
        let elems = s.split(separator: "-").map { String($0) }
        guard
            elems.count == 2,
            let low = ChildIndex.parse(elems[0]),
            let high = ChildIndex.parse(elems[1]),
            low < high
        else {
            return nil
        }
        return ChildIndexRange(low: low, high: high)
    }
}
