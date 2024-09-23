//
//  AddressTests.swift
//  AddressTests
//
//  Created by Bitcoin Dev.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Testing
import BCFoundation
import WolfBase

struct AddressTests {
    let hdKey = try! HDKey(base58: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
    let hdKeyTestnet = try! HDKey(base58: "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ")
    
    @Test func testDeriveLegacyAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToPubKeyHash)
        #expect(address† == "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
        #expect(address.taggedCBOR.cborData.hex == "d99d73a301d99d71a002000354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
    }

    @Test func testDeriveLegacyAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToPubKeyHash)
        #expect(address† == "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
        #expect(address.taggedCBOR.cborData.hex == "d99d73a301d99d71a10201020003544efd3ded47d967e4122982422c9d84db60503972")
    }

    
    @Test func testDeriveWrappedSegWitAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToScriptHashPayToWitnessPubKeyHash)
        #expect(address† == "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
        #expect(address.taggedCBOR.cborData.hex == "d99d73a301d99d71a00201035486cc442a97817c245ce90ed0d31d6dbcde3841f9")
    }
    
    @Test func testDeriveWrappedSegWitAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToScriptHashPayToWitnessPubKeyHash)
        #expect(address† == "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
        #expect(address.taggedCBOR.cborData.hex == "d99d73a301d99d71a10201020103548fb371a0195598d96e634b9eddb645fa1f128e11")
    }
    
    
    @Test func testDeriveNativeSegWitAddress() {
        let address = Bitcoin.Address(hdKey: hdKey, type: .payToWitnessPubKeyHash)
        #expect(address† == "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")
        #expect(address.taggedCBOR.cborData.hex == "d99d73a301d99d71a002020354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
    }
    
    @Test func testDeriveNativeSegWitAddressTestnet() {
        let address = Bitcoin.Address(hdKey: hdKeyTestnet, type: .payToWitnessPubKeyHash)
        #expect(address† == "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
        #expect(address.taggedCBOR.cborData.hex == "d99d73a301d99d71a10201020203544efd3ded47d967e4122982422c9d84db60503972")
    }
    
    @Test func testParseLegacyAddress() throws {
        let address = Bitcoin.Address(string: "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")!
        #expect(address.scriptPubKey == ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac"))
        #expect(address.scriptPubKey† == "pkh:[OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG]")
        #expect(address.data.hex == "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        #expect(address.type == .payToPubKeyHash)

        let cbor = address.taggedCBOR.cborData
        #expect(cbor.hex == "d99d73a301d99d71a002000354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        #expect(address == address2)
    }
    
    @Test func testParseWrappedSegWitAddress() throws {
        let address = Bitcoin.Address(string: "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")!
        #expect(address.scriptPubKey == ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987"))
        #expect(address.scriptPubKey† == "sh:[OP_HASH160 86cc442a97817c245ce90ed0d31d6dbcde3841f9 OP_EQUAL]")
        #expect(address.data.hex == "86cc442a97817c245ce90ed0d31d6dbcde3841f9")
        #expect(address.type == .payToScriptHash)

        let cbor = address.taggedCBOR.cborData
        #expect(cbor.hex == "d99d73a301d99d71a00201035486cc442a97817c245ce90ed0d31d6dbcde3841f9")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        #expect(address == address2)
    }
    
    @Test func testParseNativeSegWitAddress() throws {
        let address = Bitcoin.Address(string: "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")!
        #expect(address.scriptPubKey == ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe"))
        #expect(address.scriptPubKey† == "wpkh:[OP_0 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe]")
        #expect(address.data.hex == "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        #expect(address.type == .payToWitnessPubKeyHash)

        let cbor = address.taggedCBOR.cborData
        #expect(cbor.hex == "d99d73a301d99d71a002020354bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        #expect(address == address2)
    }
    
    @Test func testParseTaprootAddress() throws {
        let address = Bitcoin.Address(string: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")!
        #expect(address.scriptPubKey == ScriptPubKey(hex: "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
        #expect(address.scriptPubKey† == "tr:[OP_1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]")
        #expect(address.data.hex == "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        #expect(address.type == .taproot)

        let cbor = address.taggedCBOR.cborData
        #expect(cbor.hex == "d99d73a301d99d71a0020203582079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        let address2 = try Bitcoin.Address(taggedCBOR: CBOR(cbor))
        #expect(address == address2)
    }

    @Test func testParseWIF() {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        let w = WIF(wif)!
        #expect(w.key.data.hex == "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        #expect(w.network == .mainnet)
        #expect(w.isPublicKeyCompressed == false)
    }

    @Test func testToWIF() {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let key = ECPrivateKey(‡"0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")!
        #expect(WIF(key: key, network: .mainnet, isPublicKeyCompressed: false)† == "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    }
}
