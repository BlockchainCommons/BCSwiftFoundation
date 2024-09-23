//
//  Script.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/5/21.
//

import Foundation
import WolfBase

public struct Script: Equatable, Sendable {
    public let data: Data
    
    public init(_ data: Data) {
        self.data = data
    }

    public init(ops: [ScriptOperation]) {
        self.data = Data(ops.map({$0.serialized}).joined())
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public init?(asm: String) {
        var data = Data()
        let tokens = asm.split(separator: " ").map { String($0) }
        for token in tokens {
            if let hexData = Data(hex: token) {
                data.append(ScriptOperation.data(hexData).serialized)
            } else if let opcode = ScriptOpcode(name: token) {
                data.append(opcode.rawValue)
            } else {
                return nil
            }
        }
        self.init(data)
    }
    
    public var hex: String {
        data.hex
    }
    
    public var operations: [ScriptOperation]? {
        var bytes = data.lookAhead
        var ops: [ScriptOperation] = []
        
        func pushData(count: Int) -> Bool {
            guard let dataBytes = bytes.next(count: count) else {
                return false
            }
            let data = Data(dataBytes)
            ops.append(.data(data))
            return true
        }
        
        func pushData<T>(type: T.Type) -> Bool where T: FixedWidthInteger & UnsignedInteger {
            guard let countBytes = bytes.next(count: MemoryLayout<T>.size) else {
                return false
            }
            let count = Int(deserialize(T.self, countBytes, littleEndian: true)!)
            guard pushData(count: count) else {
                return false
            }
            return true
        }

        while let byte = bytes.next() {
            switch byte {
            case 0x00:
                ops.append(.op(.op_0))
            case 0x01...0x4b:
                let count = Int(byte)
                guard pushData(count: count) else {
                    return nil
                }
            case 0x4c: // OP_PUSHDATA1
                guard pushData(type: UInt8.self) else {
                    return nil
                }
            case 0x4d: // OP_PUSHDATA2
                guard pushData(type: UInt16.self) else {
                    return nil
                }
            case 0x4e: // OP_PUSHDATA4
                guard pushData(type: UInt32.self) else {
                    return nil
                }
            case 0x4f: // OP_1NEGATE
                ops.append(.op(.op_1negate))
            case 0x50: // OP_RESERVED
                ops.append(.op(.op_reserved))
            case 0x51...0xba:
                guard let opcode = ScriptOpcode(rawValue: byte) else {
                    return nil
                }
                ops.append(.op(opcode))
            default:
                return nil
            }
        }
        
        return ops
    }
    
    public var asm: String? {
        guard let ops = operations else {
            return nil
        }
        return ops.map({$0.description}).joined(separator: " ")
    }
}

extension Script: CustomStringConvertible {
    public var description: String {
        asm ?? "invalid"
    }
}
