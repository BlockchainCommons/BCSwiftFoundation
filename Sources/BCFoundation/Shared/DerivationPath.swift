//
//  DerivationPath.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
import WolfBase
@_exported import URKit

public enum DerivationPathError: Error {
    case invalidDerivationPath
    case invalidDerivationPathComponents
    case invalidPathComponent
    case invalidSourceFingerprint
    case invalidDepth
}

public struct DerivationPath : Equatable {
    public var origin: Origin?
    public var steps: [DerivationStep]
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
    
    public init(steps: [DerivationStep], origin: Origin? = nil, depth: Int? = nil) {
        self.steps = steps
        self.origin = origin
        self.depth = depth
    }

    public init?(rawPath: [UInt32], origin: Origin? = nil, depth: Int? = nil) {
        let steps = rawPath.map { DerivationStep(rawValue: $0) }
        self.init(steps: steps, origin: origin, depth: depth)
    }
    
    public init(origin: Origin?, depth: Int? = nil) {
        self.steps = []
        self.origin = origin
        self.depth = depth
    }
    
    public init(step: DerivationStep, origin: Origin? = nil, depth: Int? = nil) {
        self.init(steps: [step], origin: origin, depth: depth)
    }
    
    public init(index: ChildIndex, origin: Origin? = nil, depth: Int? = nil) {
        let step = DerivationStep(.index(index))
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
        
        var steps: [DerivationStep] = []
        components.forEach {
            guard let step = DerivationStep(string: String($0)) else {
                return
            }
            steps.append(step)
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
    
    public func rawPath(wildcardChildNum: UInt32? = nil) -> [UInt32?] {
        steps.map { $0.rawValue(wildcardChildNum: wildcardChildNum) }
    }
    
    public func dropFirst(_ k: Int) -> DerivationPath? {
        if k > steps.count {
            return nil
        }
        var newSteps = self.steps
        newSteps.removeFirst(k)
        return DerivationPath(steps: newSteps, origin: nil)
    }
    
    public func toString(format: DerivationStepFormat = .tickMark) -> String {
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
        steps.first! == DerivationStep(44, isHardened: true)
    }
    
    public var isBIP48: Bool {
        steps.count == 6 &&
        steps.first == DerivationStep(48, isHardened: true)
    }
    
    public var isBIP44Change: Bool {
        guard isBIP44,
           steps[3] == 1,
           !steps[4].isHardened,
           case let .index(i) = steps[4].childIndexSpec,
           i <= 999999
        else {
            return false
        }
        return true
    }
    
    public var isBIP48Change: Bool {
        guard isBIP48,
           steps[4] == 1,
           !steps[5].isHardened,
           case let .index(i) = steps[5].childIndexSpec,
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
    public init(arrayLiteral elements: DerivationStep...) {
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

extension DerivationPath {
    public var cbor: CBOR {
        var a: [OrderedMapEntry] = [
            .init(key: 1, value: .array(steps.flatMap { $0.array } ))
        ]
        
        if case let .fingerprint(sourceFingerprint) = origin {
            a.append(.init(key: 2, value: .unsignedInt(UInt64(sourceFingerprint))))
        }
        
        if let depth = depth {
            a.append(.init(key: 3, value: .unsignedInt(UInt64(depth))))
        }
        
        return CBOR.orderedMap(a)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(URType.derivationPath.tag, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.map(pairs) = cbor
        else {
            throw DerivationPathError.invalidDerivationPath
        }
        
        guard
            case let CBOR.array(componentsItem) = pairs[1] ?? CBOR.null,
            componentsItem.count.isMultiple(of: 2)
        else {
            throw DerivationPathError.invalidDerivationPathComponents
        }
        
        let steps: [DerivationStep] = try stride(from: 0, to: componentsItem.count, by: 2).map { i in
            let childIndexSpec = try ChildIndexSpec.decode(cbor: componentsItem[i])
            guard case let CBOR.boolean(isHardened) = componentsItem[i + 1] else {
                throw DerivationPathError.invalidPathComponent
            }
            return DerivationStep(childIndexSpec, isHardened: isHardened)
        }
        
        let origin: Origin?
        if let sourceFingerprintItem = pairs[2] {
            guard
                case let CBOR.unsignedInt(sourceFingerprintValue) = sourceFingerprintItem,
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
        if let depthItem = pairs[3] {
            guard
                case let CBOR.unsignedInt(depthValue) = depthItem,
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
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(URType.derivationPath.tag, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
}
