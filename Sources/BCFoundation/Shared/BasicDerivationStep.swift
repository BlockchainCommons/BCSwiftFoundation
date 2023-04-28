import Foundation
import SecureComponents

public struct BasicDerivationStep : DerivationStep {
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
        if rawValue < WallyExtKey.initialHardenedChild {
            self.childIndexSpec = .index(ChildIndex(rawValue)!)
            self.isHardened = false
        } else {
            self.childIndexSpec = .index(ChildIndex(rawValue - WallyExtKey.initialHardenedChild)!)
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
    
    public func rawValue(chain: Chain? = nil, addressIndex: UInt32? = nil) -> UInt32? {
        let childNum: UInt32?
        if case let .index(num) = childIndexSpec {
            childNum = num.value
        } else {
            childNum = addressIndex
        }
        guard let childNum = childNum else {
            return nil
        }
        if isHardened {
            return childNum + WallyExtKey.initialHardenedChild
        } else {
            return childNum
        }
    }
    
    public func resolve(chain: Chain?, addressIndex: UInt32?) -> BasicDerivationStep? {
        if isFixed {
            return self
        }
        guard let childNum = rawValue(chain: chain, addressIndex: addressIndex) else {
            return nil
        }
        return Self(rawValue: childNum)
    }

    public func toString(format: HardenedDerivationFormat = .tickMark) -> String {
        childIndexSpec.description + (isHardened ? format.string : "")
    }
    
    public var isFixed: Bool {
        childIndexSpec.isFixed
    }
}

extension BasicDerivationStep: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(ChildIndex(UInt32(value))!, isHardened: false)
    }
}

extension BasicDerivationStep {
    public var array: [CBOR] {
        [childIndexSpec.cbor, isHardened.cbor]
    }
}
