//
//  BIP39Tests.swift
//  BIP39Tests
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons on 27/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md.
//

import Testing
import BCFoundation
import WolfBase
import Foundation

struct BIP39Tests {
    let validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let validMnemonic24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

    @Test func testGetWordList() {
        // Check length
        #expect(BIP39.allWords.count == 2048)
        
        // Check first word
        #expect(BIP39.allWords.first == "abandon")
    }
    
    @Test func testMnemonicIsValid() {
        #expect(BIP39(mnemonic: validMnemonic) != nil)
        #expect(BIP39(mnemonic: "notavalidword") == nil)
        #expect(BIP39(mnemonic: "abandon") == nil)
        #expect(BIP39(words: ["abandon", "abandon"]) == nil)
    }
    
    @Test func testInitializeMnemonic() {
        let mnemonic = BIP39(mnemonic: validMnemonic)!
        #expect(mnemonic.words == validMnemonic.components(separatedBy: " "))
    }
    
    @Test func testInitializeMnemonicFromBytes() {
        let bytes = [Int8](repeating: 0, count: 32)
        let entropy = Data(bytes: bytes, count: 32)
        let mnemonic = BIP39(data: entropy)!
        #expect(mnemonic.words == validMnemonic24.components(separatedBy: " "))
    }
    
    @Test func testInitializeInvalidMnemonic() {
        #expect(BIP39(words: ["notavalidword"]) == nil)
    }
    
    @Test func testMnemonicLosslessStringConvertible() {
        let mnemonic = BIP39(mnemonic: validMnemonic)!
        #expect(mnemonic† == validMnemonic)
    }
    
    @Test func testMnemonicToEntropy() {
        let mnemonic = BIP39(mnemonic: validMnemonic)!
        #expect(mnemonic.data == ‡"00000000000000000000000000000000")
        let mnemonic2 = BIP39(mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow")!
        #expect(mnemonic2.data == ‡"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
    }
    
    @Test func testEntropyToMnemonic() {
        let expectedMnemonic = BIP39(mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow")!
        let entropy = ‡"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
        let mnemonic = BIP39(data: entropy)
        #expect(mnemonic == expectedMnemonic)
    }
        
    @Test func testMnemonicToSeedHexString() {
        let bip39 = BIP39(mnemonic: validMnemonic)!
        #expect(BIP39.Seed(bip39: bip39, passphrase: "TREZOR")† == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
        #expect(BIP39.Seed(bip39: bip39)† == "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
        #expect(BIP39.Seed(bip39: bip39, passphrase: "")† == "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    }
    
    @Test func testSeedLosslessStringConvertible() {
        let bip39 = BIP39(mnemonic: validMnemonic)!
        let expectedSeed = BIP39.Seed(bip39: bip39, passphrase: "TREZOR")
        let parsedSeed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
        #expect(parsedSeed == expectedSeed)
    }

    @Test func testDecodeIncompleteMnemonicWords() throws {
        let mnemonic = "fly mule exce reso trea plun nose soda refl adul ramp plan"
        let bip39 = BIP39(mnemonic: mnemonic)!
        #expect(bip39.description == "fly mule excess resource treat plunge nose soda reflect adult ramp planet")
    }
}
