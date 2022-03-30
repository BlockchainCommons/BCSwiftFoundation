//
//  ScriptPubKey.swift
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
@_exported import BCWally

public struct ScriptPubKey : Equatable {
    public let script: Script

    public enum ScriptType {
        case `return`   // OP_RETURN
        case pk         // P2PK
        case pkh        // P2PKH (legacy)
        case sh         // P2SH (could be wrapped SegWit)
        case wpkh       // P2WPKH (native SegWit)
        case wsh        // P2WSH (native SegWit script)
        case multi      // MultiSig
        case tr         // Taproot
    }

    public var type: ScriptType? {
        if let type = Wally.getType(from: self) {
            return type
        } else if
            let ops = script.operations,
            ops.count == 2,
            case .data = ops[0],
            case .op(.op_checksig) = ops[1]
        {
            return .pk
        }
        return nil
    }
    
    public init(_ data: Data) {
        self.script = Script(data)
    }

    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.script = Script(data)
    }
    
    public init(multisig pubKeys: [ECPublicKey], threshold: UInt, isBIP67: Bool = true) {
        self = Wally.multisigScriptPubKey(pubKeys: pubKeys, threshold: threshold, isBIP67: isBIP67)
    }

    public init(_ script: Script) {
        self.script = script
    }

    public var witnessProgram: Script {
        Wally.witnessProgram(scriptPubKey: self)
    }
    
    public var hex: String {
        script.hex
    }
    
    public var asm: String? {
        script.asm
    }
    
    public var multisigInfo: (Int, Int)? {
        guard
            type == .multi,
            let operations = script.operations,
            let n = operations[0].intValue,
            let m = operations[operations.count - 2].intValue,
            n <= m
        else {
            return nil
        }
        
        return (n, m)
    }
}

extension ScriptPubKey: CustomStringConvertible {
    public var description: String {
        let typeString: String
        if let type = type {
            typeString = String(describing: type)
        } else {
            typeString = "unknown"
        }
        return "\(typeString):[\(script.description)]"
    }
}

extension ScriptPubKey {
    public func data(at index: Int) -> Data? {
        guard case let .data(data) = script.operations![index] else {
            return nil
        }
        return data
    }
}
