//
//  ChildIndexSpec.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
@_exported import URKit

public enum ChildIndexSpec: Equatable {
    case index(ChildIndex)
    case indexRange(ChildIndexRange)
    case indexWildcard
    
    public var isFixed: Bool {
        switch self {
        case .index:
            return true
        default:
            return false
        }
    }
}

extension ChildIndexSpec: CustomStringConvertible {
    public var description: String {
        switch self {
        case .index(let index):
            return index.description
        case .indexRange(let indexRange):
            return indexRange.description
        case .indexWildcard:
            return "*"
        }
    }
}

extension ChildIndexSpec {
    public static func parse(_ s: String) -> ChildIndexSpec? {
        if s == "*" {
            return .indexWildcard
        } else if let range = ChildIndexRange.parse(s) {
            return .indexRange(range)
        } else if let index = ChildIndex.parse(s) {
            return .index(index)
        } else {
            return nil
        }
    }
}

extension ChildIndexSpec {
    var cbor: CBOR {
        switch self {
        case .index(let index):
            return index.cbor
        case .indexRange(let indexRange):
            return indexRange.cbor
        case .indexWildcard:
            return CBOR.array([])
        }
    }
    
    static func decode(cbor: CBOR) throws -> ChildIndexSpec {
        if let a = try ChildIndex(cbor: cbor) {
            return .index(a)
        }
        if let a = ChildIndexRange(cbor: cbor) {
            return .indexRange(a)
        }
        if parseWildcard(cbor: cbor) {
            return .indexWildcard
        }
        throw CBORError.invalidFormat
    }
    
    private static func parseWildcard(cbor: CBOR) -> Bool {
        guard case let CBOR.array(array) = cbor else {
            return false
        }
        guard array.isEmpty else {
            return false
        }
        return true
    }
}
