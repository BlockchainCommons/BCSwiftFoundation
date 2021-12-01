//
//  DerivationStep.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
@_exported import BCWally
@_exported import URKit

public struct DerivationStep : Equatable {
    public let childIndexSpec: ChildIndexSpec
    public let isHardened: Bool
    
    public var isWildcard: Bool {
        childIndexSpec == .indexWildcard
    }
    
    public init(_ childIndexSpec: ChildIndexSpec, isHardened: Bool = false) {
        self.childIndexSpec = childIndexSpec
        self.isHardened = isHardened
    }
    
    public init(_ index: ChildIndex, isHardened: Bool = false) {
        self.init(.index(index), isHardened: isHardened)
    }
    
    public init(rawValue: UInt32) {
        if rawValue < BIP32_INITIAL_HARDENED_CHILD {
            self.childIndexSpec = .index(ChildIndex(rawValue)!)
            self.isHardened = false
        } else {
            self.childIndexSpec = .index(ChildIndex(rawValue - BIP32_INITIAL_HARDENED_CHILD)!)
            self.isHardened = true
        }
    }
    
    public init?(string: String) {
        guard !string.isEmpty else {
            return nil
        }
        
        var s = string
        let isHardened: Bool
        if "'h".contains(s.last!) {
            isHardened = true
            s.removeLast()
        } else {
            isHardened = false
        }
        
        guard let childIndexSpec = ChildIndexSpec.parse(s) else {
            return nil
        }
        
        self.init(childIndexSpec, isHardened: isHardened)
    }
    
    public func rawValue(wildcardChildNum: UInt32? = nil) -> UInt32? {
        let childNum: UInt32?
        if case let .index(num) = childIndexSpec {
            childNum = num.value
        } else {
            childNum = wildcardChildNum
        }
        guard let childNum = childNum else {
            return nil
        }
        if isHardened {
            return childNum + BIP32_INITIAL_HARDENED_CHILD
        } else {
            return childNum
        }
    }
    
    public func toString(format: DerivationStepFormat = .tickMark) -> String {
        childIndexSpec.description + (isHardened ? format.string : "")
    }
    
    var isFixed: Bool {
        childIndexSpec.isFixed
    }
}

extension DerivationStep: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(ChildIndex(UInt32(value))!, isHardened: false)
    }
}

public enum DerivationStepFormat {
    case tickMark
    case letter
    
    public var string: String {
        switch self {
        case .tickMark:
            return "'"
        case .letter:
            return "h"
        }
    }
}

extension DerivationStep: CustomStringConvertible {
    public var description: String {
        toString()
    }
}

extension DerivationStep {
    var array: [CBOR] {
        [childIndexSpec.cbor, CBOR.boolean(isHardened)]
    }
}
