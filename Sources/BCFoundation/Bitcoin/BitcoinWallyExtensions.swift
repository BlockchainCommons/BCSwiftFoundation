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
    public static func hdKeyToAddress(hdKey: HDKey, type: Bitcoin.Address.AddressType) -> String {
        var key = hdKey.wallyExtKey
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        
        switch type {
        case .payToPubKeyHash, .payToScriptHashPayToWitnessPubKeyHash:
            var version: UInt32
            switch hdKey.useInfo.network {
            case .mainnet:
                version = type == .payToPubKeyHash ? 0x00 : 0x05
            case .testnet:
                version = type == .payToPubKeyHash ? 0x6F : 0xC4
            }
            precondition(wally_bip32_key_to_address(&key, type.wallyType, version, &output) == WALLY_OK)
        case .payToWitnessPubKeyHash:
            precondition(wally_bip32_key_to_addr_segwit(&key, hdKey.useInfo.network.segwitFamily, 0, &output) == WALLY_OK)
        default:
            fatalError()
        }
        
        return String(cString: output)
    }
}

extension Wally {
    public static func finalizedTransaction(psbt: WallyPSBT) -> Transaction? {
        guard let output = Wally.finalizedPSBT(psbt: psbt) else {
            return nil
        }
        defer {
            Wally.txFree(output)
        }
        return Transaction(tx: output)
    }
}

extension Wally {
    public static func getType(from scriptPubKey: ScriptPubKey) -> ScriptPubKey.ScriptType? {
        let output = Wally.getScriptType(from: scriptPubKey.script.data)

        switch Int32(output) {
        case WALLY_SCRIPT_TYPE_OP_RETURN:
            return .return
        case WALLY_SCRIPT_TYPE_P2PKH:
            return .pkh
        case WALLY_SCRIPT_TYPE_P2SH:
            return .sh
        case WALLY_SCRIPT_TYPE_P2WPKH:
            return .wpkh
        case WALLY_SCRIPT_TYPE_P2WSH:
            return .wsh
        case WALLY_SCRIPT_TYPE_MULTISIG:
            return .multi
        case WALLY_SCRIPT_TYPE_P2TR:
            return .tr
        default:
            precondition(output == WALLY_SCRIPT_TYPE_UNKNOWN)
            return nil
        }
    }
    
    public static func multisigScriptPubKey(publicKeys:[ECPublicKeyProtocol], threshold: UInt, isBIP67: Bool = true) -> ScriptPubKey {
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
