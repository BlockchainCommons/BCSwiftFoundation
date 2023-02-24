//
//  ChildIndexSpec.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
import URKit

public enum ChildIndexSpec: Equatable {
    case index(ChildIndex)
    case indexRange(ChildIndexRange)
    case indexWildcard
    case coinTypePlaceholder
    case accountPlaceholder
    
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
        case .coinTypePlaceholder:
            return "COIN_TYPE"
        case .accountPlaceholder:
            return "ACCOUNT"
        }
    }
}

extension ChildIndexSpec {
    public static func parse(_ s: String) -> ChildIndexSpec? {
        if s == "*" {
            return .indexWildcard
        } else if s == "COIN_TYPE" {
            return .coinTypePlaceholder
        } else if s == "ACCOUNT" {
            return .accountPlaceholder
        } else if let range = ChildIndexRange.parse(s) {
            return .indexRange(range)
        } else if let index = ChildIndex.parse(s) {
            return .index(index)
        } else {
            return nil
        }
    }
}


extension ChildIndexSpec: CBORCodable {
    public var cbor: CBOR {
        switch self {
        case .index(let childIndex):
            return childIndex.cbor
        case .indexRange(let childIndexRange):
            return childIndexRange.cbor
        case .indexWildcard:
            return [].cbor
        default:
            fatalError()
        }
    }
    
    public init(cbor: CBOR) throws {
        if let a = try? ChildIndex(cbor: cbor) {
            self = .index(a)
        } else if let a = try? ChildIndexRange(cbor: cbor) {
            self = .indexRange(a)
        } else if ChildIndexSpec.parseWildcard(cbor: cbor) {
            self = .indexWildcard
        } else {
            throw CBORDecodingError.invalidFormat
        }
    }
}

extension ChildIndexSpec {
    private static func parseWildcard(cbor: CBOR) -> Bool {
        guard
            case let CBOR.array(array) = cbor,
            array.isEmpty
        else {
            return false
        }
        return true
    }
}
