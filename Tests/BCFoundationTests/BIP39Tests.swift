//
//  BIP39Tests.swift
//  BIP39Tests
//
//  Created by Sjors on 27/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md.
//

import XCTest
@testable import BCFoundation
import WolfBase

class BIP39Tests: XCTestCase {
    let validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let validMnemonic24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

    func testGetWordList() {
        // Check length
        XCTAssertEqual(BIP39.allWords.count, 2048)
        
        // Check first word
        XCTAssertEqual(BIP39.allWords.first, "abandon")
    }
    
    func testMnemonicIsValid() {
        XCTAssertNotNil(BIP39(mnemonic: validMnemonic))
        XCTAssertNil(BIP39(mnemonic: "notavalidword"))
        XCTAssertNil(BIP39(mnemonic: "abandon"))
        XCTAssertNil(BIP39(words: ["abandon", "abandon"]))
    }
    
    func testInitializeMnemonic() {
        let mnemonic = BIP39(mnemonic: validMnemonic)!
        XCTAssertEqual(mnemonic.words, validMnemonic.components(separatedBy: " "))
    }
    
    func testInitializeMnemonicFromBytes() {
        let bytes = [Int8](repeating: 0, count: 32)
        let entropy = Data(bytes: bytes, count: 32)
        let mnemonic = BIP39(data: entropy)!
        XCTAssertEqual(mnemonic.words, validMnemonic24.components(separatedBy: " "))
    }
    
    func testInitializeInvalidMnemonic() {
        XCTAssertNil(BIP39(words: ["notavalidword"]))
    }
    
    func testMnemonicLosslessStringConvertible() {
        let mnemonic = BIP39(mnemonic: validMnemonic)!
        XCTAssertEqual(mnemonic†, validMnemonic)
    }
    
    func testMnemonicToEntropy() {
        let mnemonic = BIP39(mnemonic: validMnemonic)!
        XCTAssertEqual(mnemonic.data.hex, "00000000000000000000000000000000")
        let mnemonic2 = BIP39(mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow")!
        XCTAssertEqual(mnemonic2.data.hex, "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
    }
    
    func testEntropyToMnemonic() {
        let expectedMnemonic = BIP39(mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow")!
        let entropy = Data(hex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")!
        let mnemonic = BIP39(data: entropy)
        XCTAssertEqual(mnemonic, expectedMnemonic)
    }
        
    func testMnemonicToSeedHexString() {
        let bip39 = BIP39(mnemonic: validMnemonic)!
        XCTAssertEqual(BIP39.Seed(bip39: bip39, passphrase: "TREZOR")†, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
        XCTAssertEqual(BIP39.Seed(bip39: bip39)†, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
        XCTAssertEqual(BIP39.Seed(bip39: bip39, passphrase: "")†, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    }
    
    func testSeedLosslessStringConvertible() {
        let bip39 = BIP39(mnemonic: validMnemonic)!
        let expectedSeed = BIP39.Seed(bip39: bip39, passphrase: "TREZOR")
        let parsedSeed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
        XCTAssertEqual(parsedSeed, expectedSeed)
    }


}
