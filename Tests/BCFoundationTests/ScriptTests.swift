//
//  ScriptTests.swift
//  ScriptTests
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Testing
import BCFoundation
import WolfBase
import Foundation

struct ScriptTests {
    @Test func testInit() {
        let asm = Script(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!.asm!
        #expect(asm == "OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG")
        let asm2 = Script(asm: asm)!.asm!
        #expect(asm == asm2)
    }
    
    func checkScriptPubKeyAsm(_ scriptPubKey: ScriptPubKey, _ expectedAsm: String) {
        let asm = scriptPubKey.script.asm!
        #expect(asm == expectedAsm)
        let s2 = ScriptPubKey(Script(asm: asm)!)
        #expect(s2 == scriptPubKey)
    }
    
    @Test func testDetectScriptPubKeyTypeP2PKH() {
        let scriptPubKey = ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!
        #expect(scriptPubKey.type == .pkh)
        
        checkScriptPubKeyAsm(scriptPubKey, "OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG")
    }

    @Test func testDetectScriptPubKeyTypeP2SH() {
        let scriptPubKey = ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")!
        #expect(scriptPubKey.type == .sh)

        checkScriptPubKeyAsm(scriptPubKey, "OP_HASH160 86cc442a97817c245ce90ed0d31d6dbcde3841f9 OP_EQUAL")
    }

    @Test func testDetectScriptPubKeyTypeNativeSegWit() {
        let scriptPubKey = ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")!
        #expect(scriptPubKey.type == .wpkh)

        checkScriptPubKeyAsm(scriptPubKey, "OP_0 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
    }

    @Test func testDetectScriptPubKeyTypeOpReturn() {
        let scriptPubKey = ScriptPubKey(hex: "6a13636861726c6579206c6f766573206865696469")!
        #expect(scriptPubKey.type == .return)

        checkScriptPubKeyAsm(scriptPubKey, "OP_RETURN 636861726c6579206c6f766573206865696469")
    }
    
    @Test func testDetectScriptPubKeyTypeTaproot() {
        let scriptPubKey = ScriptPubKey(hex: "5120d352c1c66dbc5623136f174130a5f4a965261657c18bd1f021c2902c9e8571fd")!
        #expect(scriptPubKey.type == .tr)

        checkScriptPubKeyAsm(scriptPubKey, "OP_1 d352c1c66dbc5623136f174130a5f4a965261657c18bd1f021c2902c9e8571fd")
    }

    @Test func testScriptSigP2PKH() {
        let pubKey = SecP256K1PublicKey(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!
        var scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        #expect(scriptSig.type == ScriptSig.ScriptSigType.payToPubKeyHash(pubKey))
        #expect(scriptSig.render(purpose: .signed) == nil)

        #expect(scriptSig.signature == nil)

        let script = scriptSig.render(purpose: .feeWorstCase)!
        #expect(script.data.count == 2 + Wally.ecSignatureDerMaxLowRLen + 1 + pubKey.data.count)

        scriptSig.signature = Data(hex: "01")
        let sigHashByte = Data(hex: "01")! // SIGHASH_ALL
        let signaturePush = Data(hex: "02")! + scriptSig.signature! + sigHashByte
        let pubKeyPush = Data([UInt8(pubKey.data.count)]) + pubKey.data
        #expect(scriptSig.render(purpose: .signed)?.hex == (signaturePush + pubKeyPush).hex)
    }

    @Test func testWitnessP2WPKH() {
        let pubKey = SecP256K1PublicKey(‡"03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!
        let witness = Witness(type: .payToWitnessPubKeyHash, pubKey: pubKey)
        #expect(witness.isDummy == true)

        let witnessStack = witness.createWallyStack()
        #expect(witnessStack.count == 2)

        #expect(witness.script.data == ‡"76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        let signedWitness = Witness(type: .payToWitnessPubKeyHash, pubKey: pubKey, signature: Data(hex: "01")!)
        let signedWitnessStack = signedWitness.createWallyStack()
        #expect(signedWitnessStack.count == 2)
    }

    @Test func testMultisig() {
        let pubKey1 = SecP256K1PublicKey(‡"03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")! // [3442193e/0'/1]
        let pubKey2 = SecP256K1PublicKey(‡"022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737")! // [bd16bee5/0'/1]
        let multisig = ScriptPubKey(multisig: [pubKey1, pubKey2], threshold: 2)
        #expect(multisig.type == .multi)
        #expect(multisig.script.data == ‡"5221022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a5547372103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c52ae")
        #expect(multisig.witnessProgram.data == ‡"0020ce8c526b7a6c9491ed33861f4492299c86ffa8567a75286535f317ddede3062a")

        let address = Bitcoin.Address(scriptPubKey: multisig, network: .mainnet)!
        #expect(address.string == "bc1qe6x9y6m6dj2frmfnsc05fy3fnjr0l2zk0f6jsef47vtamm0rqc4qnfnxm0")
        #expect(address.scriptPubKey† == "multi:[OP_2 022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737 03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c OP_2 OP_CHECKMULTISIG]")
        #expect(address.data == ‡"022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737")
        #expect(address.type == .payToWitnessPubKeyHash)
    }
    
    @Test func testScriptPubKeyAddress1() {
        let scriptPubKeyPKH = ScriptPubKey(‡"76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        #expect(scriptPubKeyPKH.type == .pkh)
        let addr1 = Bitcoin.Address(scriptPubKey: scriptPubKeyPKH, network: .mainnet)!
        #expect(addr1† == "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
        let addr2 = Bitcoin.Address(scriptPubKey: scriptPubKeyPKH, network: .testnet)!
        #expect(addr2† == "mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE")

        #expect(addr1.scriptPubKey† == "pkh:[OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG]")
        #expect(addr1.data == ‡"bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        #expect(addr1.type == .payToPubKeyHash)
    }
    
    @Test func testScriptPubKeyAddress2() {
        let scriptPubKeyP2SH = ScriptPubKey(‡"a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")
        #expect(scriptPubKeyP2SH.type == .sh)
        let addr1 = Bitcoin.Address(scriptPubKey: scriptPubKeyP2SH, network: .mainnet)!
        #expect(addr1† == "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
        let addr2 = Bitcoin.Address(scriptPubKey: scriptPubKeyP2SH, network: .testnet)!
        #expect(addr2† == "2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD")
        
        #expect(addr1.scriptPubKey† == "sh:[OP_HASH160 86cc442a97817c245ce90ed0d31d6dbcde3841f9 OP_EQUAL]")
        #expect(addr1.data == ‡"86cc442a97817c245ce90ed0d31d6dbcde3841f9")
        #expect(addr1.type == .payToScriptHash)
    }
    
    @Test func testScriptPubKeyAddress3() {
        let scriptP2WPKH = ScriptPubKey(‡"0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        #expect(scriptP2WPKH.type == .wpkh)
        let addr = Bitcoin.Address(scriptPubKey: scriptP2WPKH, network: .mainnet)!
        #expect(addr† == "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")

        #expect(addr.scriptPubKey† == "wpkh:[OP_0 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe]")
        #expect(addr.data == ‡"bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        #expect(addr.type == .payToWitnessPubKeyHash)
    }

    @Test func testScriptPubKeyAddress4() {
        let scriptP2WSH = ScriptPubKey(‡"0020f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd")
        #expect(scriptP2WSH.type == .wsh)
        let addr = Bitcoin.Address(scriptPubKey: scriptP2WSH, network: .mainnet)!
        #expect(addr† == "bc1qlpsgumjm2dlcljqc96c38n6q74jtn88enkr3wrz0rtp9jp6war7s2h4lrs")

        #expect(addr.scriptPubKey† == "wsh:[OP_0 f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd]")
        #expect(addr.data == ‡"f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd")
        #expect(addr.type == .payToWitnessPubKeyHash)
    }
    
    @Test func testScriptTaproot() {
        let script = Script(asm: "OP_1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")!
        let scriptPubKey = ScriptPubKey(script)
        #expect(scriptPubKey.type == .tr)
        let addr = Bitcoin.Address(scriptPubKey: scriptPubKey, network: .mainnet)!
        #expect(addr† == "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")

        #expect(addr.scriptPubKey† == "tr:[OP_1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]")
        #expect(addr.data == ‡"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        #expect(addr.type == .taproot)
    }
}
