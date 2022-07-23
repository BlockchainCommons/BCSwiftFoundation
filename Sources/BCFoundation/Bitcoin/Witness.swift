//
//  Witness.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/22/20.
//

import Foundation
import BCWally

public struct Witness {
    public let type: WitnessType
    public let pubKey: ECPublicKey
    public let signature: Data
    public let isDummy: Bool

    public enum WitnessType {
        case payToWitnessPubKeyHash // P2WPKH (native SegWit)
        case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
    }

    public init(type: WitnessType, pubKey: ECPublicKey, signature: Data, isDummy: Bool = false) {
        self.type = type
        self.pubKey = pubKey
        self.signature = signature
        self.isDummy = isDummy
    }

    public func createWallyStack() -> UnsafeMutablePointer<wally_tx_witness_stack> {
        var newStack: UnsafeMutablePointer<wally_tx_witness_stack>!
        switch type {
        case .payToWitnessPubKeyHash:
            precondition(wally_tx_witness_stack_init_alloc(2, &newStack) == WALLY_OK)

            let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
            (signature + sigHashByte).withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 0, buf.baseAddress, buf.count) == WALLY_OK)
            }
            pubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 1, buf.baseAddress, buf.count) == WALLY_OK)
            }
        case .payToScriptHashPayToWitnessPubKeyHash:
            precondition(wally_tx_witness_stack_init_alloc(2, &newStack) == WALLY_OK)

            let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
            (signature + sigHashByte).withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 0, buf.baseAddress, buf.count) == WALLY_OK)
            }
            pubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 1, buf.baseAddress, buf.count) == WALLY_OK)
            }
        }
        return newStack
    }

    // Initialize without signature argument to get a dummy signature for fee calculation
    public init(type: WitnessType, pubKey: ECPublicKey) {
        let dummySignature = Data([UInt8].init(repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN)))
        self.init(type: type, pubKey: pubKey, signature: dummySignature, isDummy: true)
    }

    public func signed(signature: Data) -> Witness {
        Witness(type: type, pubKey: pubKey, signature: signature)
    }

    public var script: Script {
        return Script(ops: [.op(.op_dup), .op(.op_hash160), .data(pubKey.hash160), .op(.op_equalverify), .op(.op_checksig)])
    }
}
