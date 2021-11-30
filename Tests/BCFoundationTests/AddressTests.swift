//
//  AddressTests.swift
//  AddressTests
//
//  Created by Bitcoin Dev on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import BCFoundation
import WolfBase

class AddressTests: XCTestCase {
    let hdKey = try! HDKey(base58: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
    let hdKeyTestnet = try! HDKey(base58: "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ")
    
    func testDeriveLegacyAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToPubKeyHash)
        XCTAssertEqual(address†, "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
    }

    func testDeriveLegacyAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToPubKeyHash)
        XCTAssertEqual(address†, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
    }

    
    func testDeriveWrappedSegWitAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToScriptHashPayToWitnessPubKeyHash)
        XCTAssertEqual(address†, "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
    }
    
    func testDeriveWrappedSegWitAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToScriptHashPayToWitnessPubKeyHash)
        XCTAssertEqual(address†, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
    }
    
    
    func testDeriveNativeSegWitAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToWitnessPubKeyHash)
        XCTAssertEqual(address†, "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")
    }
    
    func testDeriveNativeSegWitAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToWitnessPubKeyHash)
        XCTAssertEqual(address†, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
    }
    
    func testParseLegacyAddress() {
        let address = Bitcoin.Address(string: "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac"))
    }
    
    func testParseWrappedSegWitAddress() {
        let address = Bitcoin.Address(string: "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987"))
    }
    
    func testParseNativeSegWitAddress() {
        let address = Bitcoin.Address(string: "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe"))
    }
    
    func testParseTaprootAddress() {
        let address = Bitcoin.Address(string: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    }

    func testParseWIF() {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        let w = WIF(wif)!
        XCTAssertEqual(w.key.hex, "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        XCTAssertEqual(w.network, .mainnet)
        XCTAssertEqual(w.isPublicKeyCompressed, false)
    }

    func testToWIF() {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let data = Data(hex: "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")!
        let key = ECPrivateKey(data)!
        XCTAssertEqual(WIF(key: key, network: .mainnet, isPublicKeyCompressed: false)†, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    }
    
    func testMine() {
//        let wif1 = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
//        let w1 = WIF(wif1)!
//        print(w1.key.hex)

        func toAddress(_ wif: String) -> String {
            let w = WIF(wif)!
            let pubKey = w.key.public
            let desc = try! Descriptor("pkh(\(pubKey.hex))")
            let scriptPubKey = desc.scriptPubKey()!
            let address = Bitcoin.Address(scriptPubKey: scriptPubKey, network: .mainnet)!.string
            return address
        }
        
        let addresses = """
            5KSSEo99WYVjgSa3eukSzqNL8eXDHL9J1jUEX1VavcCmrg6dE6C
            5KCHFf1L7GahZPZxssymoGxz2mmYkcJPWVjhopwmYDmYi9EpJiu
            5K51suMPKbkqfw9hJvPi2mhFQ65Y2Fc8wjPdcYDG2sTb6bu5pJq
            5KfKUMkWSrNUnPwr34nD9FFE1z77A1dw15PQJUf4wxccJZJ4L2o
            5KW9ta5ZYMk2KceXqD8iGGApmiZG8ZWVfEhPBdmiDvw8fqd3TDh
            5Httr2kbSqCsqrZNjnf29DKsnx1ReAA8XNV7Wga5mdjx637JQvw
            5HwBUa9u7RhAHxU9t8NJmetBRXjbHGnueamLxJ4NGy7yr8L54d2
            5KHedzqMAMYMo1V1qatHvh5TxQ56q6QxFYetsbZByHaUdfqgqyb
            5JPQWa846FHCgJX2Hmvg4qF3aL4WssCPn2XDgodqCrazssfu4Mp
            5KTnvr6YaFb8RDVhCZmo9YuYzGVje4VJYppiaufjdrEf4jP7oY4
            5JmpUk6NfqV9Ne7jvmmWEnfBwSD4c6wPMQGKXr8NdLuFMQqjupf
            5JrtksFt4Qi5exxbj552FgjgMp5WitFvJDk2qbmPAPJJBDtRbm6
            5KaWNdgVm7CLzv8QoNitkpM6a9chh5iH4SD8XeQ2hf2aXoGrgzu
            5JEK6PDvDjHJYBBYZjEi3LbJ1bFbPD1aeMtAVWi4bC8EJZWkyBV
            5Jq1hnC49kwVbpAwEnjw3PxrhKBXAPdBTjUhyYHzW13nm6vmine
            5KXPoGdCquDhBT1q6Aem3Q5dCsnkRQYap591a6RGjYtq45RMBx2
            5KbBYhos5KPYUM1nWpt1NERETk2i9T7L2tM4qxPV9D9C6RRZrRm
            """.split(separator: "\n").map({toAddress(String($0))})
        addresses.forEach {
            print($0)
        }
//        print(w.key.hex)
//        print(w.key.public)
//        print(w.network)
//        print(w.isPublicKeyCompressed)
        
    }
}
