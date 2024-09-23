//
//  TransactionTests.swift
//  TransactionTests
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons Provoost on 18/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Testing
@testable import BCFoundation
import WolfBase

struct TransactionTests {
    let scriptPubKey = ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!
    let pubKey = SecP256K1PublicKey(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!

    @Test func testFromHash() {
        let hash = ‡"0000000000000000000000000000000000000000000000000000000000000000"
        let txHash = TxHash(hash)!
        #expect(txHash.data == hash)

        #expect(Transaction(hex: "00") == nil) // Wrong length
    }

    @Test func testOutput() {
        let output = TxOutput(scriptPubKey: scriptPubKey, amount: 1000)
        #expect(output != nil)
        #expect(output.amount == 1000)
        #expect(output.scriptPubKey == scriptPubKey)
    }

    @Test func testInput() {
        let prevTx = TxHash(‡"0000000000000000000000000000000000000000000000000000000000000000")!
        let vout: UInt32 = 0
        let amount: Satoshi = 1000
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))

        let input = TxInput(prevTx: prevTx, vout: vout, amount: amount, sig: .scriptSig(scriptSig), scriptPubKey: scriptPubKey)
        #expect(input.prevTx == prevTx)
        #expect(input.vout == 0)
        #expect(input.sequence == 0xFFFFFFFF)
        guard case let .scriptSig(ss) = input.sig else {
            preconditionFailure()
        }
        #expect(ss.type == scriptSig.type)
        #expect(input.isSigned == false)
    }

    @Test func testComposeTransaction() {
        // Input
        let prevTx = TxHash(‡"0000000000000000000000000000000000000000000000000000000000000000")!
        let vout: UInt32 = 0
        let amount: Satoshi = 1000
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        let txInput = TxInput(prevTx: prevTx, vout: vout, amount: amount, sig: .scriptSig(scriptSig), scriptPubKey: scriptPubKey)

        // Output:
        let txOutput = TxOutput(scriptPubKey: scriptPubKey, amount: 1000)

        // Transaction
        let tx = Transaction(inputs: [txInput], outputs: [txOutput])
        let wtx = tx.tx!
        #expect(wtx.version == 1)
        #expect(wtx.inputsCount == 1)
        #expect(wtx.outputsCount == 1)
    }
    
    @Test func testDeserialize() {
        let hex = "01000000010000000000000000000000000000000000000000000000000000000000000000000000006a47304402203d274300310c06582d0186fc197106120c4838fa5d686fe3aa0478033c35b97802205379758b11b869ede2f5ab13a738493a93571268d66b2a875ae148625bd20578012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711cffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac00000000"
        let tx = Transaction(hex: hex)!
        #expect(tx† == hex)
    }
    
}

struct TransactionInstanceTests {
    let legacyInputBytes: Int = 192
    let nativeSegWitInputBytes: Int = 113
    let wrappedSegWitInputBytes: Int = 136

    // From: legacy P2PKH address 1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj
    // To: legacy P2PKH address 1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj
    let scriptPubKey1 = ScriptPubKey(‡"76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
    let pubKey = SecP256K1PublicKey(‡"03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!
    var tx1: Transaction! = nil
    var tx2: Transaction! = nil
    var tx3: Transaction! = nil
    var hdKey: HDKey! = nil // private key for signing
    
    init() {
        // Input (legacy P2PKH)
        let prevTx = TxHash(‡"0000000000000000000000000000000000000000000000000000000000000000")!
        let vout: UInt32 = 0
        let amount1: Satoshi = 1000 + Satoshi(legacyInputBytes)
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        let txInput1 = TxInput(prevTx: prevTx, vout: vout, amount: amount1, sig: .scriptSig(scriptSig), scriptPubKey: scriptPubKey1)

        // Input (native SegWit)
        let witness = Witness(type: .payToWitnessPubKeyHash, pubKey: pubKey)
        let amount2: Satoshi = 1000 + Satoshi(nativeSegWitInputBytes)
        let scriptPubKey2 = ScriptPubKey(‡"0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        let txInput2 = TxInput(prevTx: prevTx, vout: vout, amount: amount2, sig: .witness(witness), scriptPubKey: scriptPubKey2)

        // Input (wrapped SegWit)
        let witness3 = Witness(type: .payToScriptHashPayToWitnessPubKeyHash, pubKey: pubKey)
        let amount3: Satoshi = 1000 + Satoshi(wrappedSegWitInputBytes)
        let scriptPubKey3 = ScriptPubKey(‡"a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")
        let txInput3 = TxInput(prevTx: prevTx, vout: vout, amount: amount3, sig: .witness(witness3), scriptPubKey: scriptPubKey3)
        
        // Output:
        let txOutput = TxOutput(scriptPubKey: scriptPubKey1, amount: 1000)
        
        // Transaction spending legacy
        tx1 = Transaction(inputs: [txInput1], outputs: [txOutput])
        
        // Transaction spending native SegWit
        tx2 = Transaction(inputs: [txInput2], outputs: [txOutput])
        
        // Transaction spending wrapped SegWit
        tx3 = Transaction(inputs: [txInput3], outputs: [txOutput])
        
        // Corresponding private key
        hdKey = try! HDKey(base58: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
    }

    @Test func testTotalIn() {
        #expect(tx1.totalIn == 1000 + Satoshi(legacyInputBytes))
        #expect(tx2.totalIn == 1000 + Satoshi(nativeSegWitInputBytes))
        #expect(tx3.totalIn == 1000 + Satoshi(wrappedSegWitInputBytes))
    }
    
    @Test func testTotalOut() {
        #expect(tx1.totalOut == 1000)
    }
    
    @Test func testFunded() {
        #expect(tx1.isFunded == true)
    }
    
    @Test func testSize() {
        #expect(tx1.vbytes == legacyInputBytes)
        #expect(tx2.vbytes == nativeSegWitInputBytes)
        #expect(tx3.vbytes == wrappedSegWitInputBytes)
    }
    
    @Test func testFee() {
        #expect(tx1.fee == Satoshi(legacyInputBytes))
    }
    
    @Test func testFeeRate() {
        #expect(tx1.feeRate == 1.0)
        #expect(tx2.feeRate == 1.0)
        #expect(tx3.feeRate == 1.0)
    }
    
    @Test func testSign() {
        let signedTx = tx1.signed(with: [hdKey])!
        #expect(signedTx.inputs![0].isSigned)
        #expect(signedTx† == "01000000010000000000000000000000000000000000000000000000000000000000000000000000006a47304402203d274300310c06582d0186fc197106120c4838fa5d686fe3aa0478033c35b97802205379758b11b869ede2f5ab13a738493a93571268d66b2a875ae148625bd20578012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711cffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac00000000")

        #expect(signedTx.vbytes == legacyInputBytes - 1)
    }
    
    @Test func testSignNativeSegWit() {
        let signedTx = tx2.signed(with: [hdKey])!
        #expect(signedTx.inputs![0].isSigned)
        #expect(signedTx† == "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac0247304402204094361e267c39fb942b3d30c6efb96de32ea0f81e87fc36c53e00de2c24555c022069f368ac9cacea21be7b5e7a7c1dad01aa244e437161d000408343a4d6f5da0e012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c00000000")

        #expect(signedTx.vbytes == nativeSegWitInputBytes)
    }

    @Test func testSignWrappedSegWit() {
        let signedTx = tx3.signed(with: [hdKey])!
        #expect(signedTx.inputs![0].isSigned)
        #expect(signedTx† == "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000017160014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbeffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac024730440220514e02e6d4aff5e1bfcf72a98eab3a415176c757e2bf6feb7ccb893f8ffcf09b022048fe33e6a1dc80585f30aac20f58442d711739ac07d192a3a7867a1dbef6b38d012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c00000000")

        #expect(signedTx.vbytes == wrappedSegWitInputBytes)
    }
}
