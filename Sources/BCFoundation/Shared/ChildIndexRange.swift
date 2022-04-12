//
//  ChildIndexRange.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
@_exported import URKit

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

extension ChildIndexRange {
    public var untaggedCBOR: CBOR {
        CBOR.array([
            CBOR.unsignedInt(UInt64(low.value)),
            CBOR.unsignedInt(UInt64(high.value))
        ])
    }
    
    public init?(cbor: CBOR) {
        guard case let CBOR.array(array) = cbor else {
            return nil
        }
        guard array.count == 2 else {
            return nil
        }
        guard
            case let CBOR.unsignedInt(low) = array[0],
            case let CBOR.unsignedInt(high) = array[1]
        else {
            return nil
        }
        guard
            let low = ChildIndex(UInt32(low)),
            let high = ChildIndex(UInt32(high))
        else {
            return nil
        }
        self.init(
            low: low,
            high: high
        )
    }
}
