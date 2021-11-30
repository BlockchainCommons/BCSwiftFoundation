//
//  AccountTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/17/21.
//

import XCTest
import BCFoundation
import WolfBase

class AccountTests: XCTestCase {
    func testBitcoinAccount() {
        let mnemonic = "surge mind remove galaxy define nephew surge helmet shine hurry voyage dawn"
        let account = Account(mnemonic: mnemonic, useInfo: UseInfo(asset: .btc, network: .mainnet), account: 0)!
        XCTAssertEqual(account.seed!.bip39†, mnemonic)
        XCTAssertEqual(account.bip39Seed†, "414e34710a1ed4e25fb9f3568c6a81e8b7823f3f6ebd83012a7b8d9305914db074b68bf4b9b162c11a90648498736a527c2fb3f58693eada4b9c88c7f00f00a4")
        XCTAssertEqual(account.masterKey?.base58†, "xprv9s21ZrQH143K4TAgo7AZM1q8qTsQdfwMBeDHkzvbn7nadYjGPhqCzZrSTw72ykMRdUnUzvuJyfCH5W3NA7AK5MnWuBL8BYms3GSX7CHQth2")
        XCTAssertEqual(account.accountKey?.base58†, "xprv9yrG3hhrfp5KxBk8R5wbJQ7aCWq3Y4FmrLyJ6x9RiQ1Gzihjj1NBd2Bk92RmHUsKyiuXV3CjaDGNkvxaM1WRQZcLvVCq1WyMHxiTFmzw5F2")
        XCTAssertEqual(account.accountECPrivateKey†, "de3a724d167fe7a93dbdf1f5301847e04b1f45614e359c26f3990454c3e99add")
        XCTAssertEqual(account.accountECPublicKey†, "03ad4c3d4ad6d7d31bfc956e0d535fef3ddf41e91b0f7a23c76500b872603dab77")
        XCTAssertEqual(account.bitcoinAddress(type: .payToWitnessPubKeyHash)†, "bc1qqv23kswf23kh40ehql9zadlxv8rxn0663afuzu")
        XCTAssertEqual(account.bitcoinAddress(type: .payToPubKeyHash)†, "1HJK5aUGvzwFzaLXPuL9K8UaKN6Y2ifsT")
    }

    func testEthereumAccount() {
        let mnemonic = "surge mind remove galaxy define nephew surge helmet shine hurry voyage dawn"
        let account = Account(mnemonic: mnemonic, useInfo: UseInfo(asset: .eth, network: .mainnet), account: 0)!
        XCTAssertEqual(account.seed!.bip39†, mnemonic)
        XCTAssertEqual(account.bip39Seed†, "414e34710a1ed4e25fb9f3568c6a81e8b7823f3f6ebd83012a7b8d9305914db074b68bf4b9b162c11a90648498736a527c2fb3f58693eada4b9c88c7f00f00a4")
        XCTAssertEqual(account.masterKey?.base58†, "xprv9s21ZrQH143K4TAgo7AZM1q8qTsQdfwMBeDHkzvbn7nadYjGPhqCzZrSTw72ykMRdUnUzvuJyfCH5W3NA7AK5MnWuBL8BYms3GSX7CHQth2")
        XCTAssertEqual(account.accountKey?.base58†, "xprvA3Feztt4T2Y2HFVzytE7xak14RkeMeEGSQNQV6CwY8UKg2GpgJPepTN8qFKT2dJrvjDiRkCj4FbmLpszVja4Rdhmu2MQPPspKrD82iinDNp")
        XCTAssertEqual(account.accountECPrivateKey†, "c668cea9dc7ad3e2ab81c059dfe48970f10277279853f825464815825876e99f")
        XCTAssertEqual(account.accountECPublicKey†, "035d6ad3906f3cb2264a3081feaf97c82b89fd94fa1d95e7a582c771932209a49c")
        XCTAssertEqual(account.ethereumAddress†, "0x23eafe61740052028664870b02bd17bf9905c1ea")
        XCTAssertEqual(account.ethereumAddress!.shortString, "23ea...c1ea")
    }
}
