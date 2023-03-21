//
//  AddressTests.swift
//  AddressTests
//
//  Created by Bitcoin Dev.
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
        XCTAssertEqual(address.taggedCBOR.cborData.hex, "d90133a301d90131a002000354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
    }

    func testDeriveLegacyAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToPubKeyHash)
        XCTAssertEqual(address†, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
        XCTAssertEqual(address.taggedCBOR.cborData.hex, "d90133a301d90131a10201020003544efd3ded47d967e4122982422c9d84db60503972")
    }

    
    func testDeriveWrappedSegWitAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToScriptHashPayToWitnessPubKeyHash)
        XCTAssertEqual(address†, "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
        XCTAssertEqual(address.taggedCBOR.cborData.hex, "d90133a301d90131a00201035486cc442a97817c245ce90ed0d31d6dbcde3841f9")
    }
    
    func testDeriveWrappedSegWitAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToScriptHashPayToWitnessPubKeyHash)
        XCTAssertEqual(address†, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
        XCTAssertEqual(address.taggedCBOR.cborData.hex, "d90133a301d90131a10201020103548fb371a0195598d96e634b9eddb645fa1f128e11")
    }
    
    
    func testDeriveNativeSegWitAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToWitnessPubKeyHash)
        XCTAssertEqual(address†, "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")
        XCTAssertEqual(address.taggedCBOR.cborData.hex, "d90133a301d90131a002020354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
    }
    
    func testDeriveNativeSegWitAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToWitnessPubKeyHash)
        XCTAssertEqual(address†, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
        XCTAssertEqual(address.taggedCBOR.cborData.hex, "d90133a301d90131a10201020203544efd3ded47d967e4122982422c9d84db60503972")
    }
    
    func testParseLegacyAddress() throws {
        let address = Bitcoin.Address(string: "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac"))
        XCTAssertEqual(address.scriptPubKey†, "pkh:[OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(address.data.hex, "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        XCTAssertEqual(address.type, .payToPubKeyHash)

        let cbor = address.taggedCBOR.cborData
        XCTAssertEqual(cbor.hex, "d90133a301d90131a002000354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        XCTAssertEqual(address, address2)
    }
    
    func testParseWrappedSegWitAddress() throws {
        let address = Bitcoin.Address(string: "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987"))
        XCTAssertEqual(address.scriptPubKey†, "sh:[OP_HASH160 86cc442a97817c245ce90ed0d31d6dbcde3841f9 OP_EQUAL]")
        XCTAssertEqual(address.data.hex, "86cc442a97817c245ce90ed0d31d6dbcde3841f9")
        XCTAssertEqual(address.type, .payToScriptHash)

        let cbor = address.taggedCBOR.cborData
        XCTAssertEqual(cbor.hex, "d90133a301d90131a00201035486cc442a97817c245ce90ed0d31d6dbcde3841f9")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        XCTAssertEqual(address, address2)
    }
    
    func testParseNativeSegWitAddress() throws {
        let address = Bitcoin.Address(string: "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe"))
        XCTAssertEqual(address.scriptPubKey†, "wpkh:[OP_0 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe]")
        XCTAssertEqual(address.data.hex, "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        XCTAssertEqual(address.type, .payToWitnessPubKeyHash)

        let cbor = address.taggedCBOR.cborData
        XCTAssertEqual(cbor.hex, "d90133a301d90131a002020354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        XCTAssertEqual(address, address2)
    }
    
    func testParseTaprootAddress() throws {
        let address = Bitcoin.Address(string: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")!
        XCTAssertEqual(address.scriptPubKey, ScriptPubKey(hex: "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
        XCTAssertEqual(address.scriptPubKey†, "tr:[OP_1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]")
        XCTAssertEqual(address.data.hex, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        XCTAssertEqual(address.type, .taproot)

        let cbor = address.taggedCBOR.cborData
        XCTAssertEqual(cbor.hex, "d90133a301d90131a0020203582079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        XCTAssertEqual(address, address2)
    }

    func testParseWIF() {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        let w = WIF(wif)!
        XCTAssertEqual(w.key.data.hex, "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        XCTAssertEqual(w.network, .mainnet)
        XCTAssertEqual(w.isPublicKeyCompressed, false)
    }

    func testToWIF() {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let key = ECPrivateKey(‡"0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")!
        XCTAssertEqual(WIF(key: key, network: .mainnet, isPublicKeyCompressed: false)†, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    }
}
