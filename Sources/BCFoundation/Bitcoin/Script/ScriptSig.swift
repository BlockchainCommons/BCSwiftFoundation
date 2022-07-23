//
//  ScriptSig.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/22/20.
//

import Foundation
import BCWally

public struct ScriptSig {
    public let type: ScriptSigType

    // When used in a finalized transaction, scriptSig usually includes a signature:
    public var signature: Data?

    public enum ScriptSigType : Equatable {
        case payToPubKeyHash(ECPublicKey) // P2PKH (legacy)
        case payToScriptHashPayToWitnessPubKeyHash(ECPublicKey) // P2SH-P2WPKH (wrapped SegWit)
    }

    public init(type: ScriptSigType) {
        self.type = type
        self.signature = nil
    }

    public enum ScriptSigPurpose {
        case signed
        case feeWorstCase
    }

    public func render(purpose: ScriptSigPurpose) -> Script? {
        switch type {
        case .payToPubKeyHash(let pubKey):
            switch purpose {
            case .feeWorstCase:
                // DER encoded signature
                let dummySignature = Data([UInt8].init(repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN)))
                let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
                let lengthPushSignature = Data([UInt8(dummySignature.count + 1)]) // DER encoded signature + sighash byte
                let lengthPushPubKey = Data([UInt8(pubKey.data.count)])
                return Script(lengthPushSignature + dummySignature + sigHashByte + lengthPushPubKey + pubKey.data)
            case .signed:
                if let signature = signature {
                    let lengthPushSignature = Data([UInt8(signature.count + 1)]) // DER encoded signature + sighash byte
                    let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
                    let lengthPushPubKey = Data([UInt8(pubKey.data.count)])
                    return Script(lengthPushSignature + signature + sigHashByte + lengthPushPubKey + pubKey.data)
                } else {
                    return nil
                }
            }
        case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
            let redeemScript = Script(ops: [.op(.op_0), .data(pubKey.hash160)])
            return Script(ops: [.data(redeemScript.data)])
        }
    }
}
