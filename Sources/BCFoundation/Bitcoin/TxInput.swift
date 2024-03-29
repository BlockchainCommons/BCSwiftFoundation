//
//  TxInput.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation

public struct TxInput {
    public let prevTx: TxHash
    public let vout: UInt32
    public let sequence: UInt32
    public let amount: Satoshi
    public var sig: Sig
    public let scriptPubKey: ScriptPubKey
    
    public enum Sig {
        case scriptSig(ScriptSig)
        case witness(Witness)
    }

    // For P2SH wrapped SegWit, we set scriptSig automatically
    public init(prevTx: TxHash, vout: UInt32, sequence: UInt32 = 0xffffffff, amount: Satoshi, sig: Sig, scriptPubKey: ScriptPubKey) {
        self.prevTx = prevTx
        self.vout = vout
        self.sequence = sequence
        self.amount = amount
        self.sig = sig
        self.scriptPubKey = scriptPubKey
    }

    public func createWallyInput() -> WallyTxInput {
        let witness: WallyWitnessStack?
        if case let .witness(w) = sig {
            witness = w.createWallyStack()
        } else {
            witness = nil
        }
        return WallyTxInput(prevTx: prevTx.data, vout: vout, sequence: sequence, amount: amount, witness: witness)
    }

    public var isSigned: Bool {
        switch sig {
        case .scriptSig(let scriptSig):
            return scriptSig.signature != nil
        case .witness(let witness):
            return !witness.isDummy
        }
    }
}
