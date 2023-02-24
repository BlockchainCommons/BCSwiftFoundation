//
//  BitcoinAddress.swift
//  Address 
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import URKit

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

        public init?(scriptPubKey: ScriptPubKey, useInfo: UseInfo) {
            self.useInfo = useInfo
            let network = useInfo.network
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
            case .wpkh, .wsh:
                self.string = Wally.segwitAddress(scriptPubKey: scriptPubKey, network: network)
                self.data = scriptPubKey.data(at: 1)!
                self.type = .payToWitnessPubKeyHash
            case .tr:
                self.string = Wally.segwitAddress(scriptPubKey: scriptPubKey, network: network)
                self.data = scriptPubKey.data(at: 1)!
                self.type = .taproot
            case .multi:
                self.string = Wally.segwitAddress(script: scriptPubKey.witnessProgram, network: network)
                self.data = scriptPubKey.data(at: 1)!
                self.type = .payToWitnessPubKeyHash
            default:
                return nil
            }
        }
        
        public init?(scriptPubKey: ScriptPubKey, network: Network) {
            self.init(scriptPubKey: scriptPubKey, useInfo: UseInfo(network: network))
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
            
            var cborType: CBORType {
                switch self {
                case .payToPubKeyHash:
                    return .p2pkh
                case .payToScriptHash, .payToScriptHashPayToWitnessPubKeyHash:
                    return .p2sh
                case .payToWitnessPubKeyHash, .taproot:
                    return .p2wpkh
                }
            }
        }
        
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-009-address.md#cddl
        public enum CBORType: Int {
            case p2pkh
            case p2sh
            case p2wpkh

            public var untaggedCBOR: CBOR {
                CBOR.unsigned(UInt64(rawValue))
            }

            public init(untaggedCBOR: CBOR) throws {
                guard
                    case let CBOR.unsigned(r) = untaggedCBOR,
                    let a = CBORType(rawValue: Int(r)) else {
                        throw CBORDecodingError.invalidFormat
                    }
                self = a
            }
        }
        
        public var description: String {
            string
        }
    }
}

extension Bitcoin.Address: CBORTaggedCodable {
    public static var cborTag: DCBOR.Tag = .address
    
    public var untaggedCBOR: CBOR {
        // https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-009-address.md#cddl
        let a: Map = [
            1: useInfo.taggedCBOR,
            2: type.cborType.rawValue,
            3: data
        ]
        return a.cbor
    }

    public init(untaggedCBOR: CBOR) throws {
        guard case CBOR.map(let map) = untaggedCBOR else {
            throw CBORDecodingError.invalidFormat
        }

        let useInfo: UseInfo
        if let rawUseInfo = map[1] {
            useInfo = try UseInfo(taggedCBOR: rawUseInfo)
        } else {
            useInfo = UseInfo()
        }

        guard
            let typeItem = map[2]
        else {
            throw CBORDecodingError.invalidFormat
        }
        let cborType = try CBORType(untaggedCBOR: typeItem)

        guard
            let dataItem = map[3],
            case let CBOR.bytes(bytes) = dataItem,
            !bytes.isEmpty
        else {
             // CBOR doesn't contain data field
            throw CBORDecodingError.invalidFormat
        }
        let data = bytes.data
        
        let scriptPubKey: ScriptPubKey
        
        switch cborType {
        case .p2pkh:
            scriptPubKey = ScriptPubKey(Script(ops: [.op(.op_dup), .op(.op_hash160), .data(data), .op(.op_equalverify), .op(.op_checksig)]))
        case .p2sh:
            scriptPubKey = ScriptPubKey(Script(ops: [.op(.op_hash160), .data(data), .op(.op_equal)]))
        case .p2wpkh:
            switch(data.count) {
            case 20:
                scriptPubKey = ScriptPubKey(Script(ops: [.op(.op_0), .data(data)]))
            case 32:
                scriptPubKey = ScriptPubKey(Script(ops: [.op(.op_1), .data(data)]))
            default:
                throw CBORDecodingError.invalidFormat
            }
        }
        
        self.init(scriptPubKey: scriptPubKey, useInfo: useInfo)!
    }
}
