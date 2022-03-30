//
//  PSBTOutput.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
@_exported import BCWally

public struct PSBTOutput {
    public let txOutput: TxOutput
    public let origins: [PSBTSigningOrigin]

    public func address(network: Network) -> String {
        txOutput.address(network: network)
    }
    
    public var amount: Satoshi {
        txOutput.amount
    }

    init(wallyPSBTOutput: WallyPSBTOutput, wallyTxOutput: wally_tx_output) {
        if wallyPSBTOutput.keypaths.num_items > 0 {
            self.origins = getOrigins(keypaths: wallyPSBTOutput.keypaths)
        } else {
            self.origins = []
        }
        let scriptPubKey: ScriptPubKey
        if let scriptPubKeyBytes = wallyPSBTOutput.witness_script {
            scriptPubKey = ScriptPubKey(Script(Data(bytes: scriptPubKeyBytes, count: wallyPSBTOutput.witness_script_len)))
        } else {
            scriptPubKey = ScriptPubKey(Script(Data(bytes: wallyTxOutput.script, count: wallyTxOutput.script_len)))
        }

        self.txOutput = TxOutput(scriptPubKey: scriptPubKey, amount: wallyTxOutput.satoshi)
    }

    static func commonOriginChecks(originPath: DerivationPath, rootPathLength: Int, pubKey: ECPublicKey, signer: HDKey, cosigners: [HDKey]) ->  Bool {
        // Check that origin ends with 0/* or 1/*
        let steps = originPath.steps
        if steps.count < 2 ||
                !(steps.reversed()[1] == .init(0) || steps.reversed()[1] == .init(1)) ||
            steps.reversed()[0].isHardened
        {
            return false
        }

        // Find matching HDKey
        var hdKey: HDKey? = nil
        guard let signerMasterKeyFingerprint = signer.originFingerprint else {
            return false
        }
        guard
            let pathOrigin = originPath.origin,
            case .fingerprint(let originFingerprint) = pathOrigin else {
            return false
        }
        if signerMasterKeyFingerprint == originFingerprint {
            hdKey = signer
        } else {
            for cosigner in cosigners {
                guard let cosignerMasterKeyFingerprint = cosigner.originFingerprint else {
                    return false
                }
                if cosignerMasterKeyFingerprint == originFingerprint {
                    hdKey = cosigner
                }
            }
        }

        guard let hdKey = hdKey else {
            return false
        }

        // Check that origin pubkey is correct
        guard let childKey = try? HDKey(parent: hdKey, childDerivationPath: originPath) else {
            return false
        }

        if childKey.ecPublicKey != pubKey {
            return false
        }

        return true
    }
    
    public var isChange: Bool {
        !origins.isEmpty && origins.allSatisfy { $0.isChange }
    }

    public func isChange(signer: HDKey, inputs:[PSBTInput], cosigners: [HDKey], threshold: UInt) -> Bool {
        // Transaction must have at least one input
        if inputs.count < 1 {
            return false
        }

        // All inputs must have origin info
        for input in inputs {
            if input.origins.isEmpty {
                return false
            }
        }

        // Skip key deriviation root
        let keyPath = inputs[0].origins.first!.path
        if keyPath.steps.count < 2 {
            return false
        }
        let keyPathRootLength = keyPath.steps.count - 2

        for input in inputs {
            // Check that we can sign all inputs (TODO: relax assumption for e.g. coinjoin)
            if !input.canSign(with: signer) {
                return false
            }
            
            let origins = input.origins
            guard !origins.isEmpty else {
                return false
            }

            for origin in origins {
                if !(PSBTOutput.commonOriginChecks(originPath: origin.path, rootPathLength:keyPathRootLength, pubKey: origin.key, signer: signer, cosigners: cosigners)) {
                    return false
                }
            }
        }

        // Check outputs
        guard !origins.isEmpty else {
            return false
        }

        var changeIndex: ChildIndex? = nil
        for origin in origins {
            if !(PSBTOutput.commonOriginChecks(originPath: origin.path, rootPathLength:keyPathRootLength, pubKey: origin.key, signer: signer, cosigners: cosigners)) {
                return false
            }
            // Check that the output index is reasonable
            // When combined with the above constraints, change "hijacked" to an extreme index can
            // be covered by importing keys using Bitcoin Core's maximum range [0,999999].
            // This needs less than 1 GB of RAM, but is fairly slow.
            let step = origin.path.steps.reversed()[0]
            if !step.isHardened {
                guard case let .index(i) = step.childIndexSpec else {
                    return false
                }
                if i > 999999 {
                    return false
                }
                // Change index must be the same for all origins
                if changeIndex != nil && i != changeIndex {
                    return false
                } else {
                    changeIndex = i
                }
            }
        }

        // Check scriptPubKey
        switch self.txOutput.scriptPubKey.type {
        case .multi:
            let expectedScriptPubKey = ScriptPubKey(multisig: Array(origins.map({ $0.key })), threshold: threshold)
            if self.txOutput.scriptPubKey != expectedScriptPubKey {
                return false
            }
        default:
            return false
        }
        return true
    }
}

extension PSBTOutput {
    public func signingStatus<SignerType: PSBTSigner>(origin: PSBTSigningOrigin, signers: [SignerType]) -> PSBTSigningStatus<SignerType> {
        if let signer = signers.first(where: {
            try! HDKey(parent: $0.masterKey, childDerivationPath: origin.path).ecPublicKey == origin.key
        }) {
            return PSBTSigningStatus(origin: origin, isSigned: false, knownSigner: signer)
        } else {
            return PSBTSigningStatus(origin: origin, isSigned: false, knownSigner: nil)
        }
    }
    
    public func signingStatus<SignerType: PSBTSigner>(signers: [SignerType]) -> [PSBTSigningStatus<SignerType>] {
        origins.map { signingStatus(origin: $0, signers: signers) }
    }
}
