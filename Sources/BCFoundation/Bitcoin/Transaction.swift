//
//  Transaction.swift
//  Transaction
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons Provoost on 18/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import WolfBase
@_exported import BCWally

public struct Transaction {
    public let inputs: [TxInput]?
    public let outputs: [TxOutput]?

    private var storage: Storage

    private final class Storage {
        var tx: WallyTx?

        init(tx: WallyTx) { self.tx = tx }

        init() { self.tx = nil }

        deinit { wally_tx_free(tx) }
    }

    var tx: WallyTx? {
        storage.tx
    }

    private static func clone(tx: WallyTx) -> WallyTx {
        var newTx: WallyTx!
        precondition(wally_tx_clone_alloc(tx, 0, &newTx) == WALLY_OK)
        return newTx
    }

    private mutating func prepareForWrite() {
        if
            !isKnownUniquelyReferenced(&storage),
            let tx = storage.tx
        {
            storage.tx = Self.clone(tx: tx)
        }
    }

    init(tx: WallyTx) {
        inputs = nil
        outputs = nil
        storage = Storage(tx: Self.clone(tx: tx))
    }

    public init?(_ data: Data) {
        inputs = nil
        outputs = nil
        guard
            let newTx = Wally.txFromBytes(data)
        else {
            return nil
        }
        storage = Storage(tx: newTx)
    }

    public init?(hex: String) {
        self.init(Data(hex: hex))
    }

    public init(inputs: [TxInput], outputs: [TxOutput]) {
        self.inputs = inputs
        self.outputs = outputs
        
        let version: UInt32 = 1
        let lockTime: UInt32 = 0

        var wtx: WallyTx!
        precondition(wally_tx_init_alloc(version, lockTime, inputs.count, outputs.count, &wtx) == WALLY_OK)

        for input in inputs {
            Wally.txAddInput(tx: wtx, input: input.createWallyInput())
        }

        for output in outputs {
            Wally.txAddOutput(tx: wtx, output: output.createWallyOutput())
        }

        storage = Storage(tx: wtx)
    }

    private init(inputs: [TxInput]?, outputs: [TxOutput]?, tx: WallyTx) {
        self.inputs = inputs
        self.outputs = outputs
        self.storage = Storage(tx: tx)
    }

    var totalIn: Satoshi? {
        guard let inputs = inputs else { return nil }
        return inputs.reduce(0) {
            $0 + $1.amount
        }
    }
    
    var totalOut: Satoshi? {
        guard let tx = tx else { return nil }
        return Wally.txGetTotalOutputSatoshi(tx: tx)
    }
    
    var isFunded: Bool? {
        guard let totalOut = totalOut, let totalIn = totalIn else { return nil }
        return totalOut <= totalIn
    }
    
    public var vbytes: Int? {
        guard
            let tx = tx,
            let inputs = inputs
        else {
            return nil
        }

        let cloned_tx = Self.clone(tx: tx)
        defer {
            wally_tx_free(cloned_tx)
        }

        // Set scriptSig for all unsigned inputs to .feeWorstCase
        for (index, input) in inputs.enumerated() {
            if !input.isSigned {
                let scriptSig: ScriptSig?
                switch input.sig {
                case .scriptSig(let ss):
                    scriptSig = ss
                case .witness(let witness):
                    if witness.type == .payToScriptHashPayToWitnessPubKeyHash {
                        scriptSig = ScriptSig(type: .payToScriptHashPayToWitnessPubKeyHash(witness.pubKey))
                    } else {
                        scriptSig = nil
                    }
                }
                
                if let scriptSig = scriptSig {
                    let scriptSigWorstCase = scriptSig.render(purpose: .feeWorstCase)!.data
                    Wally.txSetInputScript(tx: cloned_tx, index: index, script: scriptSigWorstCase)
                }
            }
        }
        
        return Wally.txGetVsize(tx: cloned_tx)
    }
    
    public var fee: Satoshi? {
        guard let totalOut = totalOut, let totalIn = totalIn, totalIn >= totalOut else { return nil }
        return totalIn - totalOut
    }
    
    public var feeRate: Float64? {
        guard let fee = fee, let vbytes = vbytes else { return nil }
        precondition(vbytes > 0)
        return Float64(fee) / Float64(vbytes)
    }
    
    public func signed(with privKeys: [HDKey]) -> Transaction? {
        guard let tx = tx else {
            // No transaction to sign.
            return nil
        }
        guard let inputs = inputs else {
            // No inputs to sign.
            return nil
        }
        if privKeys.count != inputs.count {
            // Wrong number of keys to sign.
            return nil
        }

        let cloned_tx = Self.clone(tx: tx)

        var updatedInputs = inputs

        // Loop through inputs to sign:
        for i in 0 ..< inputs.count {
            let messageHash: Data

            switch inputs[i].sig {
            case .witness(let witness):
                switch witness.type {
                case .payToScriptHashPayToWitnessPubKeyHash:
                    let scriptSig = ScriptSig(type: .payToScriptHashPayToWitnessPubKeyHash(witness.pubKey)).render(purpose: .signed)!.data
                    Wally.txSetInputScript(tx: cloned_tx, index: i, script: scriptSig)
                    
                    fallthrough
                case .payToWitnessPubKeyHash:
                    // Check that we're using the right public key:
                    let pubKeyData = Data(of: privKeys[i].wallyExtKey.pub_key)
                    precondition(witness.pubKey.data == pubKeyData)
                    
                    messageHash = Wally.txGetBTCSignatureHash(tx: cloned_tx, index: i, script: witness.script.data, amount: inputs[i].amount, isWitness: true)
                }
            case .scriptSig:
                // Prep input for signing:
                messageHash = Wally.txGetBTCSignatureHash(tx: cloned_tx, index: i, script: inputs[i].scriptPubKey.script.data, amount: 0, isWitness: false)
            }

            let compactSig: Data

            // Sign hash using private key (without 0 prefix)
            precondition(EC_MESSAGE_HASH_LEN == SHA256_LEN)
            
            var privKey = Data(of: privKeys[i].wallyExtKey.priv_key)
            // skip prefix byte 0
            precondition(privKey.popFirst() != nil)

            // Ensure private key is valid
            precondition(Wally.ecPrivateKeyVerify(privKey))
        
            compactSig = Wally.ecSigFromBytes(privKey: privKey, messageHash: messageHash)
        
            // Check that signature is valid and for the correct public key:
            precondition(Wally.ecSigVerify(key: privKeys[i].wallyExtKey, messageHash: messageHash, compactSig: compactSig))

            // Convert to low s form:
            let sigNorm = Wally.ecSigNormalize(compactSig: compactSig)
            
            // Convert normalized signature to DER
            let signature = Wally.ecSigToDer(sigNorm: sigNorm)

            // Store signature in TxInput
            switch inputs[i].sig {
            case .witness(let witness):
                let witness = witness.signed(signature: signature)
                updatedInputs[i].sig = .witness(witness)
                precondition(wally_tx_set_input_witness(cloned_tx, i, witness.createWallyStack()) == WALLY_OK)
            case .scriptSig(var scriptSig):
                scriptSig.signature = signature
                updatedInputs[i].sig = .scriptSig(scriptSig)
                
                // Update scriptSig:
                let signedScriptSig = scriptSig.render(purpose: .signed)!.data
                Wally.txSetInputScript(tx: cloned_tx, index: i, script: signedScriptSig)
            }
        }

        return Transaction(inputs: updatedInputs, outputs: outputs, tx: cloned_tx)
    }

}

extension Transaction: CustomStringConvertible {
    public var description: String {
        guard let tx = tx else { return "nil" }

        // If we have TxInput objects, make sure they're all signed. Otherwise we've been initialized
        // from a hex string, so we'll just try to reserialize what we have.
        if let inputs = inputs {
            for input in inputs {
                if !input.isSigned {
                    return "nil"
                }
            }
        }
        
        return Wally.txToHex(tx: tx)
    }
}
