//
//  Witness.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/22/20.
//

import Foundation

public struct Witness {
    public let type: WitnessType
    public let pubKey: SecP256K1PublicKey
    public let signature: Data
    public let isDummy: Bool

    public enum WitnessType {
        case payToWitnessPubKeyHash // P2WPKH (native SegWit)
        case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
    }

    public init(type: WitnessType, pubKey: SecP256K1PublicKey, signature: Data, isDummy: Bool = false) {
        self.type = type
        self.pubKey = pubKey
        self.signature = signature
        self.isDummy = isDummy
    }

    public func createWallyStack() -> WallyWitnessStack {
        let sigHashByte = Data([Wally.sighashAll])
        switch type {
        case .payToWitnessPubKeyHash:
            let witness0 = signature + sigHashByte
            let witness1 = pubKey.data
            return WallyWitnessStack([witness0, witness1])
        case .payToScriptHashPayToWitnessPubKeyHash:
            let witness0 = signature + sigHashByte
            let witness1 = pubKey.data
            return WallyWitnessStack([witness0, witness1])
        }
    }

    // Initialize without signature argument to get a dummy signature for fee calculation
    public init(type: WitnessType, pubKey: SecP256K1PublicKey) {
        let dummySignature = Data([UInt8].init(repeating: 0, count: Wally.ecSignatureDerMaxLowRLen))
        self.init(type: type, pubKey: pubKey, signature: dummySignature, isDummy: true)
    }

    public func signed(signature: Data) -> Witness {
        Witness(type: type, pubKey: pubKey, signature: signature)
    }

    public var script: Script {
        return Script(ops: [.op(.op_dup), .op(.op_hash160), .data(pubKey.hash160), .op(.op_equalverify), .op(.op_checksig)])
    }
}
