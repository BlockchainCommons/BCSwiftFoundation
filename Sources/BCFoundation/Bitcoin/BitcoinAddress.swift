//
//  BitcoinAddress.swift
//  Address 
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import BCWally

extension Bitcoin {
    open class Address: AddressProtocol {
        public let useInfo: UseInfo
        public let scriptPubKey: ScriptPubKey
        public let string: String
        
        public init?(string: String) {
            self.string = string
            
            // Try if this is a bech32 Bitcoin mainnet address:
            if let scriptPubKey = Wally.segwitAddressToScriptPubKey(address: string, network: .mainnet) {
                self.useInfo = UseInfo(asset: .btc, network: .mainnet)
                self.scriptPubKey = scriptPubKey
                return
            }
            
            // Try if this is a bech32 Bitcoin testnet address:
            if let scriptPubKey = Wally.segwitAddressToScriptPubKey(address: string, network: .testnet) {
                self.useInfo = UseInfo(asset: .btc, network: .testnet)
                self.scriptPubKey = scriptPubKey
                return
            }
            
            // Try if this is a base58 addresses (P2PKH or P2SH)
            if let scriptPubKey = Wally.addressToScriptPubKey(address: string, network: .mainnet) {
                self.useInfo = UseInfo(asset: .btc, network: .mainnet)
                self.scriptPubKey = scriptPubKey
                return
            }
            
            // Try if this is a testnet base58 addresses (P2PKH or P2SH)
            if let scriptPubKey = Wally.addressToScriptPubKey(address: string, network: .testnet) {
                self.useInfo = UseInfo(asset: .btc, network: .testnet)
                self.scriptPubKey = scriptPubKey
                return
            }
            
            return nil
        }
        
        public convenience init(hdKey: HDKey, type: AddressType) {
            let address = Wally.hdKeyToAddress(hdKey: hdKey, type: type)
            self.init(string: address)!
        }
        
        public init?(scriptPubKey: ScriptPubKey, network: Network) {
            self.useInfo = UseInfo(asset: .btc, network: network)
            self.scriptPubKey = scriptPubKey
            switch scriptPubKey.type {
            case .pkh, .sh:
                self.string = Wally.address(from: scriptPubKey, network: network)
            case .wpkh, .wsh, .tr:
                self.string = Wally.segwitAddress(scriptPubKey: scriptPubKey, network: network)
            case .multi:
                self.string = Wally.segwitAddress(script: scriptPubKey.witnessProgram, network: network)
            default:
                return nil
            }
        }
        
        public enum AddressType {
            case payToPubKeyHash // P2PKH (legacy)
            case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
            case payToWitnessPubKeyHash // P2WPKH (native SegWit)
            
            var wallyType: UInt32 {
                switch self {
                case .payToPubKeyHash:
                    return UInt32(WALLY_ADDRESS_TYPE_P2PKH)
                case .payToScriptHashPayToWitnessPubKeyHash:
                    return UInt32(WALLY_ADDRESS_TYPE_P2SH_P2WPKH)
                case .payToWitnessPubKeyHash:
                    return UInt32(WALLY_ADDRESS_TYPE_P2WPKH)
                }
            }
        }
        
        open var description: String {
            string
        }
    }
}
