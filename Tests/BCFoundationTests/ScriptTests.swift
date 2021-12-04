//
//  ScriptTests.swift
//  ScriptTests
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import BCFoundation
import WolfBase

class ScriptTests: XCTestCase {
    func testInit() {
        let asm = Script(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!.asm!
        XCTAssertEqual(asm, "OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG")
        let asm2 = Script(asm: asm)!.asm!
        XCTAssertEqual(asm, asm2)
    }
    
    func checkScriptPubKeyAsm(_ scriptPubKey: ScriptPubKey, _ expectedAsm: String) {
        let asm = scriptPubKey.script.asm!
        XCTAssertEqual(asm, expectedAsm)
        let s2 = ScriptPubKey(Script(asm: asm)!)
        XCTAssertEqual(s2, scriptPubKey)
    }
    
    func testDetectScriptPubKeyTypeP2PKH() {
        let scriptPubKey = ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!
        XCTAssertEqual(scriptPubKey.type, .pkh)
        
        checkScriptPubKeyAsm(scriptPubKey, "OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG")
    }

    func testDetectScriptPubKeyTypeP2SH() {
        let scriptPubKey = ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")!
        XCTAssertEqual(scriptPubKey.type, .sh)

        checkScriptPubKeyAsm(scriptPubKey, "OP_HASH160 86cc442a97817c245ce90ed0d31d6dbcde3841f9 OP_EQUAL")
    }

    func testDetectScriptPubKeyTypeNativeSegWit() {
        let scriptPubKey = ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")!
        XCTAssertEqual(scriptPubKey.type, .wpkh)

        checkScriptPubKeyAsm(scriptPubKey, "OP_0 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
    }

    func testDetectScriptPubKeyTypeOpReturn() {
        let scriptPubKey = ScriptPubKey(hex: "6a13636861726c6579206c6f766573206865696469")!
        XCTAssertEqual(scriptPubKey.type, .return)

        checkScriptPubKeyAsm(scriptPubKey, "OP_RETURN 636861726c6579206c6f766573206865696469")
    }
    
    func testDetectScriptPubKeyTypeTaproot() {
        let scriptPubKey = ScriptPubKey(hex: "5120d352c1c66dbc5623136f174130a5f4a965261657c18bd1f021c2902c9e8571fd")!
        XCTAssertEqual(scriptPubKey.type, .tr)

        checkScriptPubKeyAsm(scriptPubKey, "OP_1 d352c1c66dbc5623136f174130a5f4a965261657c18bd1f021c2902c9e8571fd")
    }

    func testScriptSigP2PKH() {
        let pubKey = ECCompressedPublicKey(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!
        var scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        XCTAssertEqual(scriptSig.type, ScriptSig.ScriptSigType.payToPubKeyHash(pubKey))
        XCTAssertEqual(scriptSig.render(purpose: .signed), nil)

        XCTAssertEqual(scriptSig.signature, nil)

        let script = scriptSig.render(purpose: .feeWorstCase)!
        XCTAssertEqual(script.data.count, 2 + Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN) + 1 + pubKey.data.count)

        scriptSig.signature = Data(hex: "01")
        let sigHashByte = Data(hex: "01")! // SIGHASH_ALL
        let signaturePush = Data(hex: "02")! + scriptSig.signature! + sigHashByte
        let pubKeyPush = Data([UInt8(pubKey.data.count)]) + pubKey.data
        XCTAssertEqual(scriptSig.render(purpose: .signed)?.hex, (signaturePush + pubKeyPush).hex)
    }

    func testWitnessP2WPKH() {
        let pubKey = ECCompressedPublicKey(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!
        let witness = Witness(type: .payToWitnessPubKeyHash, pubKey: pubKey)
        XCTAssertEqual(witness.isDummy, true)

        let witnessStack = witness.createWallyStack()
        defer { wally_tx_witness_stack_free(witnessStack) }
        XCTAssertEqual(witnessStack.pointee.num_items, 2)

        XCTAssertEqual(witness.script.hex, "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        let signedWitness = Witness(type: .payToWitnessPubKeyHash, pubKey: pubKey, signature: Data(hex: "01")!)
        let signedWitnessStack = signedWitness.createWallyStack()
        defer { wally_tx_witness_stack_free(signedWitnessStack) }
        XCTAssertEqual(signedWitnessStack.pointee.num_items, 2)
    }

    func testMultisig() {
        let pubKey1 = ECCompressedPublicKey(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")! // [3442193e/0'/1]
        let pubKey2 = ECCompressedPublicKey(hex: "022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737")! // [bd16bee5/0'/1]
        let multisig = ScriptPubKey(multisig: [pubKey1, pubKey2], threshold: 2)
        XCTAssertEqual(multisig.type, .multi)
        XCTAssertEqual(multisig.script.data.hex, "5221022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a5547372103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c52ae")
        XCTAssertEqual(multisig.witnessProgram.hex, "0020ce8c526b7a6c9491ed33861f4492299c86ffa8567a75286535f317ddede3062a")

        let address = Bitcoin.Address(scriptPubKey: multisig, network: .mainnet)!
        XCTAssertEqual(address.string, "bc1qe6x9y6m6dj2frmfnsc05fy3fnjr0l2zk0f6jsef47vtamm0rqc4qnfnxm0")
        XCTAssertEqual(address.scriptPubKey†, "multi:[OP_2 022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737 03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c OP_2 OP_CHECKMULTISIG]")
        XCTAssertEqual(address.data.hex, "022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737")
        XCTAssertEqual(address.type, .payToWitnessPubKeyHash)
    }
    
    func testScriptPubKeyAddress1() {
        let scriptPubKeyPKH = ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!
        XCTAssertEqual(scriptPubKeyPKH.type, .pkh)
        let addr1 = Bitcoin.Address(scriptPubKey: scriptPubKeyPKH, network: .mainnet)!
        XCTAssertEqual(addr1†, "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
        let addr2 = Bitcoin.Address(scriptPubKey: scriptPubKeyPKH, network: .testnet)!
        XCTAssertEqual(addr2†, "mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE")

        XCTAssertEqual(addr1.scriptPubKey†, "pkh:[OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(addr1.data.hex, "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        XCTAssertEqual(addr1.type, .payToPubKeyHash)
    }
    
    func testScriptPubKeyAddress2() {
        let scriptPubKeyP2SH = ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")!
        XCTAssertEqual(scriptPubKeyP2SH.type, .sh)
        let addr1 = Bitcoin.Address(scriptPubKey: scriptPubKeyP2SH, network: .mainnet)!
        XCTAssertEqual(addr1†, "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
        let addr2 = Bitcoin.Address(scriptPubKey: scriptPubKeyP2SH, network: .testnet)!
        XCTAssertEqual(addr2†, "2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD")
        
        XCTAssertEqual(addr1.scriptPubKey†, "sh:[OP_HASH160 86cc442a97817c245ce90ed0d31d6dbcde3841f9 OP_EQUAL]")
        XCTAssertEqual(addr1.data.hex, "86cc442a97817c245ce90ed0d31d6dbcde3841f9")
        XCTAssertEqual(addr1.type, .payToScriptHash)
    }
    
    func testScriptPubKeyAddress3() {
        let scriptP2WPKH = ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")!
        XCTAssertEqual(scriptP2WPKH.type, .wpkh)
        let addr = Bitcoin.Address(scriptPubKey: scriptP2WPKH, network: .mainnet)!
        XCTAssertEqual(addr†, "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")

        XCTAssertEqual(addr.scriptPubKey†, "wpkh:[OP_0 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe]")
        XCTAssertEqual(addr.data.hex, "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        XCTAssertEqual(addr.type, .payToWitnessPubKeyHash)
    }

    func testScriptPubKeyAddress4() {
        let scriptP2WSH = ScriptPubKey(hex: "0020f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd")!
        XCTAssertEqual(scriptP2WSH.type, .wsh)
        let addr = Bitcoin.Address(scriptPubKey: scriptP2WSH, network: .mainnet)!
        XCTAssertEqual(addr†, "bc1qlpsgumjm2dlcljqc96c38n6q74jtn88enkr3wrz0rtp9jp6war7s2h4lrs")

        XCTAssertEqual(addr.scriptPubKey†, "wsh:[OP_0 f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd]")
        XCTAssertEqual(addr.data.hex, "f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd")
        XCTAssertEqual(addr.type, .payToWitnessPubKeyHash)
    }
    
    func testScriptTaproot() {
        let script = Script(asm: "OP_1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")!
        let scriptPubKey = ScriptPubKey(script)
        XCTAssertEqual(scriptPubKey.type, .tr)
        let addr = Bitcoin.Address(scriptPubKey: scriptPubKey, network: .mainnet)!
        XCTAssertEqual(addr†, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")

        XCTAssertEqual(addr.scriptPubKey†, "tr:[OP_1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798]")
        XCTAssertEqual(addr.data.hex, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        XCTAssertEqual(addr.type, .payToWitnessPubKeyHash)
    }
}
