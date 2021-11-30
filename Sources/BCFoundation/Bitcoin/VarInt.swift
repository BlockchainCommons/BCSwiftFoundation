//
//  VarInt.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/9/21.
//

import Foundation
import WolfBase

public struct VarInt {
    public let value: Int
    
    public init?(_ value: Int) {
        guard (0...Int.max).contains(value) else {
            return nil
        }
        self.value = value
    }
    
    public init?<D>(_ data: D) where D: DataProtocol {
        guard !data.isEmpty else {
            return nil
        }
        let first = data.first!
        let remaining = data.dropFirst()
        switch first {
        case 0...252:
            self.value = Int(first)
        case 0xfd:
            guard remaining.count >= 2 else {
                return nil
            }
            let i = deserialize(UInt16.self, remaining, littleEndian: true)!
            self.value = Int(i)
        case 0xfe:
            guard remaining.count >= 4 else {
                return nil
            }
            self.value = Int(deserialize(UInt32.self, remaining, littleEndian: true)!)
        case 0xff:
            guard remaining.count >= 8 else {
                return nil
            }
            self.value = Int(deserialize(UInt64.self, remaining, littleEndian: true)!)
        default:
            return nil
        }
    }

    public var serializedSize: Int {
        switch value {
        case 0...252:
            return 1
        case 253...0xffff:
            return 3
        case 0x10000...0xffffffff:
            return 5
        case 0x100000000...Int.max:
            return 9
        default:
            preconditionFailure()
        }
    }
    
    public var serialized: Data {
        switch value {
        case 0...252:
            return UInt8(value).serialized
        case 253...0xffff:
            return [UInt8(0xfd)].data + UInt16(value).serialized(littleEndian: true)
        case 0x10000...0xffffffff:
            return [UInt8(0xfe)].data + UInt32(value).serialized(littleEndian: true)
        case 0x100000000...Int.max:
            return [UInt8(0xff)].data + UInt64(value).serialized(littleEndian: true)
        default:
            preconditionFailure()
        }
    }
}

extension VarInt: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self = VarInt(value)!
    }
}

extension VarInt: Comparable {
    public static func < (lhs: VarInt, rhs: VarInt) -> Bool {
        lhs.value < rhs.value
    }
}

extension VarInt: Equatable {
    public static func == (lhs: VarInt, rhs: VarInt) -> Bool {
        lhs.value == rhs.value
    }
}
