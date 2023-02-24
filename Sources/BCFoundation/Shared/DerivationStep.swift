//
//  DerivationStep.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
import URKit

public protocol DerivationStep: Equatable, CustomStringConvertible {
    var isWildcard: Bool { get }
    var isPair: Bool { get }
    var isFixed: Bool { get }
    var isHardened: Bool { get }
    var array: [CBOR] { get }
    func rawValue(chain: Chain?, addressIndex: UInt32?) -> UInt32?
    func resolve(chain: Chain?, addressIndex: UInt32?) -> BasicDerivationStep?
    func toString(format: HardenedDerivationFormat) -> String
}

extension DerivationStep {
    public var description: String {
        toString(format: .tickMark)
    }
    
    public var isWildcard: Bool {
        false
    }

    public var isPair: Bool {
        return false
    }
}

public func isEqual(_ lhs: any DerivationStep, _ rhs: any DerivationStep) -> Bool {
    if let lhs = lhs as? BasicDerivationStep, let rhs = rhs as? BasicDerivationStep {
        return lhs == rhs
    } else if let lhs = lhs as? PairDerivationStep, let rhs = rhs as? PairDerivationStep {
        return lhs == rhs
    } else {
        return false
    }
}

public func isEqual(_ lhs: Array<any DerivationStep>, _ rhs: Array<any DerivationStep>) -> Bool {
    guard
        lhs.count == rhs.count,
        zip(lhs, rhs).allSatisfy({ isEqual($0, $1) })
    else {
        return false
    }
    
    return true
}
