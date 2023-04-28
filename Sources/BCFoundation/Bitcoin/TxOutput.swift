//
//  TxOutput.swift
//  BCFoundation
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation

public struct TxOutput {
    public let scriptPubKey: ScriptPubKey
    public var amount: Satoshi

    public func address(network: Network) -> String {
        Bitcoin.Address(scriptPubKey: self.scriptPubKey, network: network)!.description
    }

    public init(scriptPubKey: ScriptPubKey, amount: Satoshi) {
        self.scriptPubKey = scriptPubKey
        self.amount = amount
    }

    public func createWallyOutput() -> WallyTxOutput {
        WallyTxOutput(amount: amount, scriptPubKey: scriptPubKey.script.data)
    }
}

extension TxOutput: CustomStringConvertible {
    public var description: String {
        "TxOutput(scriptPubKey: \(scriptPubKey), amount: \(amount.btcFormat))"
    }
}
