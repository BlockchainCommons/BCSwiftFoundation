//
//  ChildIndex.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
import URKit

public struct ChildIndex: ExpressibleByIntegerLiteral, Comparable {
    public let value: UInt32
    public init?(_ value: UInt32) {
        guard(value & 0x80000000 == 0) else {
            return nil
        }
        self.value = value
    }
    
    public init(integerLiteral value: UInt32) {
        guard value < 0x80000000 else {
            fatalError()
        }
        self.value = value
    }
    
    public static func ==(lhs: ChildIndex, rhs: ChildIndex) -> Bool {
        return lhs.value == rhs.value
    }
    
    public static func <(lhs: ChildIndex, rhs: ChildIndex) -> Bool {
        return lhs.value < rhs.value
    }
}

extension ChildIndex: CustomStringConvertible {
    public var description: String {
        String(value)
    }
}

extension String {
    public init(_ index: ChildIndex) {
        self = index.description
    }
}

extension ChildIndex {
    public static func parse(_ s: String) -> ChildIndex? {
        guard let i = Int(s), i >= 0, i < 0x80000000 else {
            return nil
        }
        return ChildIndex(UInt32(i))!
    }
}

extension ChildIndex: CBORCodable {
    public var cbor: CBOR {
        value.cbor
    }

    public init(cbor: CBOR) throws {
        guard
            let value = try? UInt32(cbor: cbor),
            value < 0x80000000
        else {
            throw CBORError.invalidFormat
        }
        self.init(value)!
    }
}
