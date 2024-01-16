//
//  BitcoinWallyExtensions.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation
import WolfBase
import SecureComponents

extension Wally {
    public static func finalizedTransaction(psbt: WallyPSBT) -> Transaction? {
        guard let output = Wally.finalizedPSBT(psbt: psbt) else {
            return nil
        }
        defer {
            psbt.dispose()
        }
        return Transaction(tx: output)
    }
}

extension Wally {
    public static func multisigScriptPubKey(publicKeys:[any ECDSAPublicKeyProtocol], threshold: UInt, isBIP67: Bool = true) -> ScriptPubKey {
        let publicKeysData = publicKeys.map { $0.data }
        let output = Wally.multisigScriptPubKey(pubKeys: publicKeysData, threshold: threshold, isBIP67: isBIP67)
        return ScriptPubKey(Script(output))
    }
    
    public static func address(from scriptPubKey: ScriptPubKey, network: Network) -> String {
        Wally.address(from: scriptPubKey.script.data, network: network)
    }
    
    public static func segwitAddress(script: Script, network: Network) -> String {
        Wally.segwitAddress(from: script.data, network: network)
    }
    
    public static func segwitAddress(scriptPubKey: ScriptPubKey, network: Network) -> String {
        Wally.segwitAddress(script: scriptPubKey.script, network: network)
    }
    
    public static func witnessProgram(scriptPubKey: ScriptPubKey) -> Script {
        Script(Wally.witnessProgram(from: scriptPubKey.script.data))
    }

    public static func addressToScriptPubKey(address: String, network: Network) -> ScriptPubKey? {
        guard let data = Wally.addressToScript(address: address, network: network) else {
            return nil
        }
        return ScriptPubKey(Script(data))
    }

    public static func segwitAddressToScriptPubKey(address: String, network: Network) -> ScriptPubKey? {
        guard let data = Wally.segwitAddressToScript(address: address, network: network) else {
            return nil
        }
        return ScriptPubKey(Script(data))
    }
}

extension Data {
    public func base58(isCheck: Bool) -> String {
        Wally.base58(data: self, isCheck: isCheck)
    }
}
