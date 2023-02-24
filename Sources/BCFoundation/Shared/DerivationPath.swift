//
//  DerivationPath.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
import WolfBase
import URKit

public enum DerivationPathError: Error {
    case invalidDerivationPath
    case invalidDerivationPathComponents
    case invalidPathComponent
    case invalidSourceFingerprint
    case invalidDepth
}

extension DerivationPath: Equatable {
    public static func ==(lhs: Self, rhs: Self) -> Bool {
        isEqual(lhs.steps, rhs.steps)
    }
}

public struct DerivationPath {
    public var origin: Origin?
    public var steps: [any DerivationStep]
    public var depth: Int?
    
    public var isMaster: Bool {
        guard depth == nil || depth! == 0 else {
            return false
        }
        guard steps.isEmpty else {
            return false
        }
        guard origin == nil || origin! == .master else {
            return false
        }
        return true
    }
    
    public enum Origin: Equatable, CustomStringConvertible {
        case fingerprint(UInt32)
        case master
        
        public var description: String {
            switch self {
            case .fingerprint(let f):
                return f.hex
            case .master:
                return "m"
            }
        }
    }
    
    public init() {
        self.origin = nil
        self.steps = []
    }
    
    public init(steps: [any DerivationStep], origin: Origin? = nil, depth: Int? = nil) {
        self.steps = steps
        self.origin = origin
        self.depth = depth
    }

    public init?(rawPath: [UInt32], origin: Origin? = nil, depth: Int? = nil) {
        let steps = rawPath.map { BasicDerivationStep(rawValue: $0) }
        self.init(steps: steps, origin: origin, depth: depth)
    }
    
    public init(origin: Origin?, depth: Int? = nil) {
        self.steps = []
        self.origin = origin
        self.depth = depth
    }
    
    public init(step: any DerivationStep, origin: Origin? = nil, depth: Int? = nil) {
        self.init(steps: [step], origin: origin, depth: depth)
    }
    
    public init(index: ChildIndex, origin: Origin? = nil, depth: Int? = nil) {
        let step = BasicDerivationStep(.index(index))
        self.init(steps: [step], origin: origin, depth: depth)
    }
    
    public init(originFingerprint: UInt32, depth: Int? = nil) {
        self.steps = []
        self.origin = .fingerprint(originFingerprint)
        self.depth = depth
    }
    
    public init?(string: String, requireFixed: Bool = false) {
        var components = string.split(separator: "/")
        
        let origin: Origin?
        if components.isEmpty {
            origin = nil
        } else {
            let o = String(components.first!)
            if o == "m" {
                origin = .master
                components.removeFirst()
            } else if let data = Data(hex: o), data.count == 4 {
                origin = .fingerprint(deserialize(UInt32.self, data)!)
                components.removeFirst()
            } else {
                origin = nil
            }
        }
        
        var steps: [any DerivationStep] = []
        components.forEach {
            if let step = BasicDerivationStep(string: String($0)) {
                steps.append(step)
            } else if let step = PairDerivationStep(string: String($0)) {
                steps.append(step)
            }
        }
        guard steps.count == components.count else {
            return nil
        }
        
        guard !requireFixed || steps.allSatisfy({ $0.isFixed }) else {
            return nil
        }
        
        self.init(steps: steps, origin: origin)
    }
    
    public var originFingerprint: UInt32? {
        get {
            guard case let .fingerprint(fingerprint) = origin else {
                return nil
            }
            return fingerprint
        }
        
        set {
            if let f = newValue {
                origin = .fingerprint(f)
            } else {
                origin = nil
            }
        }
    }

    public var effectiveDepth: Int {
        return depth ?? steps.count
    }
    
    public var count: Int {
        steps.count
    }

    public var isEmpty: Bool {
        steps.isEmpty
    }
    
    public var hasWildcard: Bool {
        steps.contains(where: { $0.isWildcard })
    }
    
    public var hasPair: Bool {
        steps.contains(where: { $0.isPair })
    }
    
    public func rawPath(chain: Chain?, addressIndex: UInt32?) -> [UInt32?] {
        steps.map { $0.rawValue(chain: chain, addressIndex: addressIndex) }
    }
    
    public func dropFirst(_ k: Int) -> DerivationPath? {
        if k > steps.count {
            return nil
        }
        var newSteps = self.steps
        newSteps.removeFirst(k)
        return DerivationPath(steps: newSteps, origin: nil)
    }
    
    public func toString(format: HardenedDerivationFormat = .tickMark) -> String {
        var comps: [String] = []
        if let origin = origin {
            comps.append(origin.description)
        }
        for step in steps {
            comps.append(step.toString(format: format))
        }
        return comps.joined(separator: "/")
    }
    
    var isFixed: Bool {
        steps.allSatisfy { $0.isFixed }
    }
    
    var isHardened: Bool {
        steps.contains { $0.isHardened }
    }
}

extension DerivationPath {
    public var isBIP44: Bool {
        steps.count == 5 &&
        steps.first as? BasicDerivationStep == BasicDerivationStep(44, isHardened: true)
    }
    
    public var isBIP48: Bool {
        steps.count == 6 &&
        steps.first as? BasicDerivationStep == BasicDerivationStep(48, isHardened: true)
    }
    
    public var isBIP44Change: Bool {
        guard isBIP44,
              let step3 = steps[3] as? BasicDerivationStep,
              step3 == 1,
              let step4 = steps[4] as? BasicDerivationStep,
              !step4.isHardened,
              case let .index(i) = step4.childIndexSpec,
              i <= 999999
        else {
            return false
        }
        return true
    }
    
    public var isBIP48Change: Bool {
        guard isBIP48,
              let step4 = steps[4] as? BasicDerivationStep,
              step4 == 1,
              let step5 = steps[5] as? BasicDerivationStep,
              !step5.isHardened,
              case let .index(i) = step5.childIndexSpec,
              i <= 999999
        else {
            return false
        }
        return true
    }
    
    public var isChange: Bool {
        isBIP44Change || isBIP48Change
    }
}

extension DerivationPath: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: any DerivationStep...) {
        self.init(steps: elements)
    }
}

extension DerivationPath: CustomStringConvertible {
    public var description: String {
        toString()
    }
}

extension DerivationPath {
    public static func + (lhs: DerivationPath, rhs: DerivationPath) -> DerivationPath {
        DerivationPath(steps: lhs.steps + rhs.steps, origin: lhs.origin)
    }
}

extension DerivationPath: CBORTaggedCodable {
    public static var cborTag: DCBOR.Tag = .derivationPath
    
    public var untaggedCBOR: CBOR {
        var a: Map = [1: steps.flatMap { $0.array }]
        
        if case let .fingerprint(sourceFingerprint) = origin {
            a[2] = sourceFingerprint.cbor
        }
        
        if let depth = depth {
            a[3] = depth.cbor
        }
        
        return CBOR.map(a)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR
        else {
            throw DerivationPathError.invalidDerivationPath
        }

        guard
            case let CBOR.array(componentsItem) = map[1] ?? CBOR.null,
            componentsItem.count.isMultiple(of: 2)
        else {
            throw DerivationPathError.invalidDerivationPathComponents
        }
        
        let steps: [any DerivationStep] = try stride(from: 0, to: componentsItem.count, by: 2).map { i in
            let childIndexSpec = try ChildIndexSpec(cbor: componentsItem[i])
            guard let isHardened = try? Bool(cbor: componentsItem[i + 1]) else {
                throw DerivationPathError.invalidPathComponent
            }
            return BasicDerivationStep(childIndexSpec, isHardened: isHardened)
        }
        
        let origin: Origin?
        if let sourceFingerprintItem = map[2] {
            guard
                case let CBOR.unsigned(sourceFingerprintValue) = sourceFingerprintItem,
                sourceFingerprintValue != 0,
                sourceFingerprintValue <= UInt32.max
            else {
                throw DerivationPathError.invalidSourceFingerprint
            }
            origin = .fingerprint(UInt32(sourceFingerprintValue))
        } else {
            origin = nil
        }
        
        let depth: Int?
        if let depthItem = map[3] {
            guard
                case let CBOR.unsigned(depthValue) = depthItem,
                depthValue <= UInt8.max
            else {
                throw DerivationPathError.invalidDepth
            }
            depth = Int(depthValue)
        } else {
            depth = nil
        }
        
        self.init(steps: steps, origin: origin, depth: depth)
    }
}
