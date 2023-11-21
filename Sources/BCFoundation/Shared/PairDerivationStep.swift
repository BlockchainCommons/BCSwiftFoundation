import Foundation
import URKit
import WolfBase

public struct PairDerivationStep : DerivationStep {
    public let external: BasicDerivationStep
    public let `internal`: BasicDerivationStep
    
    public init(external: BasicDerivationStep, internal: BasicDerivationStep) {
        self.external = external
        self.internal = `internal`
    }
    
    public var isPair: Bool {
        true
    }
    
    public var isFixed: Bool {
        false
    }
    
    public var isHardened: Bool {
        external.isHardened || `internal`.isHardened
    }
    
    public static func ==(lhs: Self, rhs: Self) -> Bool {
        lhs.external == rhs.external && lhs.internal == rhs.internal
    }
    
    public func toString(format: HardenedDerivationFormat) -> String {
        "<\(external.toString(format: format));\(`internal`.toString(format: format))>"
    }
    
    public var array: [CBOR] {
        [CBOR.array(external.array + `internal`.array)]
    }
    
    public init?(cbor: CBOR) {
        guard 
            case CBOR.array(let array) = cbor,
            array.count == 4,
            let external = BasicDerivationStep(cbor1: array[0], cbor2: array[1]),
            let `internal` = BasicDerivationStep(cbor1: array[2], cbor2: array[3])
        else {
            return nil
        }
        self.init(external: external, internal: `internal`)
    }
    
    public func rawValue(chain: Chain?, addressIndex: UInt32?) -> UInt32? {
        resolve(chain: chain, addressIndex: addressIndex)?.rawValue()
    }

    public func resolve(chain: Chain?, addressIndex: UInt32?) -> BasicDerivationStep? {
        guard let chain else {
            return nil
        }
        switch chain {
        case .external:
            return external
        case .internal:
            return `internal`
        }
    }

    public init?(string: String) {
        todo()
        return nil
    }
}
