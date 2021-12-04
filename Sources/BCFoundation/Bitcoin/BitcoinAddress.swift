//
//  BitcoinAddress.swift
//  Address 
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
@_exported import BCWally
@_exported import URKit

extension Bitcoin {
    public struct Address: AddressProtocol {
        public let useInfo: UseInfo
        public let scriptPubKey: ScriptPubKey
        public let string: String
        public let data: Data
        public let type: AddressType
        
        public init?(string: String) {
            self.string = string
            
            // Try if this is a bech32 Bitcoin mainnet address:
            if let scriptPubKey = Wally.segwitAddressToScriptPubKey(address: string, network: .mainnet) {
                self.useInfo = UseInfo(asset: .btc, network: .mainnet)
                self.scriptPubKey = scriptPubKey
                self.data = scriptPubKey.data(at: 1)!
                if scriptPubKey.type == .tr {
                    self.type = .taproot
                } else {
                    self.type = .payToWitnessPubKeyHash
                }
                return
            }
            
            // Try if this is a bech32 Bitcoin testnet address:
            if let scriptPubKey = Wally.segwitAddressToScriptPubKey(address: string, network: .testnet) {
                self.useInfo = UseInfo(asset: .btc, network: .testnet)
                self.scriptPubKey = scriptPubKey
                self.data = scriptPubKey.data(at: 1)!
                if scriptPubKey.type == .tr {
                    self.type = .taproot
                } else {
                    self.type = .payToWitnessPubKeyHash
                }
                return
            }
            
            // Try if this is a base58 addresses (P2PKH or P2SH)
            if let scriptPubKey = Wally.addressToScriptPubKey(address: string, network: .mainnet) {
                self.useInfo = UseInfo(asset: .btc, network: .mainnet)
                self.scriptPubKey = scriptPubKey
                switch scriptPubKey.type {
                case .pkh:
                    self.data = scriptPubKey.data(at: 2)!
                    self.type = .payToPubKeyHash
                case .sh:
                    self.data = scriptPubKey.data(at: 1)!
                    self.type = .payToScriptHash
                case .wsh:
                    self.data = scriptPubKey.data(at: 1)!
                    self.type = .payToScriptHashPayToWitnessPubKeyHash
                default:
                    fatalError()
                }
                return
            }
            
            // Try if this is a testnet base58 addresses (P2PKH or P2SH)
            if let scriptPubKey = Wally.addressToScriptPubKey(address: string, network: .testnet) {
                self.useInfo = UseInfo(asset: .btc, network: .testnet)
                self.scriptPubKey = scriptPubKey
                switch scriptPubKey.type {
                case .pkh:
                    self.data = scriptPubKey.data(at: 2)!
                    self.type = .payToPubKeyHash
                case .sh:
                    self.data = scriptPubKey.data(at: 1)!
                    self.type = .payToScriptHash
                case .wsh:
                    self.data = scriptPubKey.data(at: 1)!
                    self.type = .payToScriptHashPayToWitnessPubKeyHash
                default:
                    fatalError()
                }
                return
            }
            
            return nil
        }
        
        public init(hdKey: HDKey, type: AddressType) {
            let address = Wally.hdKeyToAddress(hdKey: hdKey, type: type)
            self.init(string: address)!
        }
        
        public init?(scriptPubKey: ScriptPubKey, network: Network) {
            self.useInfo = UseInfo(asset: .btc, network: network)
            self.scriptPubKey = scriptPubKey
            switch scriptPubKey.type {
            case .pkh:
                self.string = Wally.address(from: scriptPubKey, network: network)
                self.data = scriptPubKey.data(at: 2)!
                self.type = .payToPubKeyHash
            case .sh:
                self.string = Wally.address(from: scriptPubKey, network: network)
                self.data = scriptPubKey.data(at: 1)!
                self.type = .payToScriptHash
            case .wpkh, .wsh, .tr:
                self.string = Wally.segwitAddress(scriptPubKey: scriptPubKey, network: network)
                self.data = scriptPubKey.data(at: 1)!
                self.type = .payToWitnessPubKeyHash
            case .multi:
                self.string = Wally.segwitAddress(script: scriptPubKey.witnessProgram, network: network)
                self.data = scriptPubKey.data(at: 1)!
                self.type = .payToWitnessPubKeyHash
            default:
                return nil
            }
        }
                
        public enum AddressType {
            case payToPubKeyHash // P2PKH (legacy)
            case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
            case payToWitnessPubKeyHash // P2WPKH (native SegWit)
            
            case payToScriptHash
            case taproot
            
            var wallyType: UInt32 {
                switch self {
                case .payToPubKeyHash:
                    return UInt32(WALLY_ADDRESS_TYPE_P2PKH)
                case .payToScriptHashPayToWitnessPubKeyHash:
                    return UInt32(WALLY_ADDRESS_TYPE_P2SH_P2WPKH)
                case .payToWitnessPubKeyHash:
                    return UInt32(WALLY_ADDRESS_TYPE_P2WPKH)
                default:
                    fatalError()
                }
            }
        }
        
        public var description: String {
            string
        }
    }
}

extension Bitcoin.Address {
//    public var cbor: CBOR {
//        var a: [OrderedMapEntry] = []
//
//        a.append(.init(key: 1, value: useInfo.taggedCBOR))
//
//        // 2: type omitted
//
////        a.append(.init(key: 3, value: scriptPubKey.script.data))
//    }
}
