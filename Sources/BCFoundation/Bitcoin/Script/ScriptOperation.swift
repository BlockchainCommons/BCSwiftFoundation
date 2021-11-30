//
//  ScriptOperation.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/5/21.
//

import Foundation
import WolfBase

public enum ScriptOperation: Equatable {
    case data(Data)
    case op(ScriptOpcode)
    
    public init(_ data: Data) {
        self = .data(data)
    }
    
    public init(_ opcode: ScriptOpcode) {
        self = .op(opcode)
    }
    
    public init?(_ string: String) {
        if let opcode = ScriptOpcode(name: string) {
            self = .op(opcode)
        } else if let data = Data(hex: string) {
            self = .data(data)
        } else {
            return nil
        }
    }

    public var serialized: Data {
        var result = Data()
        switch self {
        case .op(let opcode):
            result.append(opcode.rawValue)
        case .data(let data):
            let count = data.count
            switch count {
            case 0x00...0x4b:
                result.append(UInt8(count))
                result.append(data)
            case 0x4c...0xff:
                result.append(ScriptOpcode.op_pushdata1.rawValue)
                result.append(serialize(UInt8(count), littleEndian: true))
                result.append(data)
            case 0x100...0xffff:
                result.append(ScriptOpcode.op_pushdata2.rawValue)
                result.append(serialize(UInt16(count), littleEndian: true))
                result.append(data)
            case 0x10000...0xffffffff:
                result.append(ScriptOpcode.op_pushdata4.rawValue)
                result.append(serialize(UInt32(count), littleEndian: true))
                result.append(data)
            default:
                fatalError()
            }
        }
        return result
    }
}

extension ScriptOperation: CustomStringConvertible {
    public var description: String {
        switch self {
        case .data(let data):
            return data.hex
        case .op(let opcode):
            return opcode.description
        }
    }
}

extension ScriptOperation {
    public var intValue: Int? {
        guard case let .op(op) = self else {
            return nil
        }
        return op.intValue
    }
}
