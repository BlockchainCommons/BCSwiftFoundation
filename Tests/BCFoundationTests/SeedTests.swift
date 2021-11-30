//
//  SeedTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/15/21.
//

import XCTest
import BCFoundation

class SeedTests: XCTestCase {
    func testBIP39() throws {
        let mnemonic = "surge mind remove galaxy define nephew surge helmet shine hurry voyage dawn"
        let bip39 = BIP39(mnemonic: mnemonic)!
        let seed = Seed(bip39: bip39)
        XCTAssertEqual(seed.data.hex, "da519ed7af739928b69357c5edf7d81b")
        XCTAssertEqual(seed.bip39.mnemonic, mnemonic)
        
        let key = try? HDKey(seed: seed)
        XCTAssertEqual(key?.base58, "xprv9s21ZrQH143K4TAgo7AZM1q8qTsQdfwMBeDHkzvbn7nadYjGPhqCzZrSTw72ykMRdUnUzvuJyfCH5W3NA7AK5MnWuBL8BYms3GSX7CHQth2")
    }
}
