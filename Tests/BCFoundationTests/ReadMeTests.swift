//
//  ReadMeTests.swift
//  
//
//  Created by Wolf McNally on 12/3/21.
//

import XCTest
import BCFoundation

class ReadMeTests: XCTestCase {
    func testDeriveAddressFromSeed() {
        let mnemonic = BIP39(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")!
        let seed = BIP39.Seed(bip39: mnemonic, passphrase: "bip39 passphrase")
        let masterKey = try! HDKey(bip39Seed: seed)
        assert(masterKey.keyFingerprint.hex == "7b343b65")
        let path = DerivationPath(string: "m/44'/0'/0'")!
        let accountKey = try! HDKey(parent: masterKey, childDerivationPath: path)
        assert(accountKey.base58PrivateKey == "xprv9z3bixmawU269r5jUAbWbVFDY3qN6LZdHH7r28C7gmZMXPfbN8o39622JvuyvQxBYPBMEtJNetWBCyy6hZXcAEubReyb95MnJQR5bAMiR2d")
        assert(accountKey.base58PublicKey == "xpub6D2x8UJUmqaPNLACaC8WxdBx65frVoHUeW3SpWbjF76LQBzjug7HgtLWACEbNoRubqXqM9y7t822g9RpEPPxmALG8tiZYVw5Ec66swihmUy")
        assert(Bitcoin.Address(hdKey: accountKey, type: .payToWitnessPubKeyHash).description == "bc1qtqq3hzwgswm56tt3h04ss8qmmttt6py9yj8h6c")
    }
    
    func testDeriveAddressFromXpub() {
        let accountKey = try! HDKey(base58: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
        let receivePath = DerivationPath(string: "0/0")!
        let receiveKey = try! HDKey(parent: accountKey, childDerivationPath: receivePath)
        let address = Bitcoin.Address(hdKey: receiveKey, type: .payToPubKeyHash)
        assert(address.description == "1BiCdXSDHyeXSzmx2paVPFVTrmyx7BeCGD")
        assert(address.scriptPubKey.description == "pkh:[OP_DUP OP_HASH160 757c05317fcb85e910c5f3e6cd9dc4d06b5d8321 OP_EQUALVERIFY OP_CHECKSIG]")
    }
    
    func testParseAddress() {
        let address = Bitcoin.Address(string: "bc1q6zwjfmhdl4pvhvfpv8pchvtanlar8hrhqdyv0t")!
        assert(address.scriptPubKey.hex == "0014d09d24eeedfd42cbb12161c38bb17d9ffa33dc77")
        assert(address.scriptPubKey.type! == .wpkh)
        assert(address.scriptPubKey.description == "wpkh:[OP_0 d09d24eeedfd42cbb12161c38bb17d9ffa33dc77]")
    }
    
    func testCreateAndSignTransaction() {
        let pubKey = ECCompressedPublicKey(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")!
        let prevTx = TxHash(hex: "0000000000000000000000000000000000000000000000000000000000000000")!
        let vout: UInt32 = 0
        let legacyInputBytes: Int = 192
        let amount1: Satoshi = 1000 + Satoshi(legacyInputBytes)
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        let scriptPubKey1 = ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")!
        let txInput1 = TxInput(prevTx: prevTx, vout: vout, amount: amount1, sig: .scriptSig(scriptSig), scriptPubKey: scriptPubKey1)
        let hdKey = try! HDKey(base58: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        let txOutput = TxOutput(scriptPubKey: scriptPubKey1, amount: 1000)
        let tx1 = Transaction(inputs: [txInput1], outputs: [txOutput])
        let signedTx = tx1.signed(with: [hdKey])!
        assert(signedTx.inputs![0].isSigned)
        assert(signedTx.description == "01000000010000000000000000000000000000000000000000000000000000000000000000000000006a47304402203d274300310c06582d0186fc197106120c4838fa5d686fe3aa0478033c35b97802205379758b11b869ede2f5ab13a738493a93571268d66b2a875ae148625bd20578012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711cffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac00000000")
        assert(signedTx.vbytes == legacyInputBytes - 1)
    }
}
