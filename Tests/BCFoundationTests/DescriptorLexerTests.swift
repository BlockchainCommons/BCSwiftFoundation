//
//  DescriptorLexerTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 8/31/21.
//

import XCTest
@testable import BCFoundation

class DescriptorLexerTests: XCTestCase {
    func testLexDelimiters() {
        try XCTAssertEqual(DescriptorLexer.debugLex("(){},"), "(openParen 0..<1), (closeParen 1..<2), (openBrace 2..<3), (closeBrace 3..<4), (comma 4..<5)")
    }
    
    func testLexKeywords() {
        try XCTAssertEqual(DescriptorLexer.debugLex("sh,wsh,pk,pkh,wpkh,combo,multi,sortedmulti,tr,addr,raw"), "(sh 0..<2), (comma 2..<3), (wsh 3..<6), (comma 6..<7), (pk 7..<9), (comma 9..<10), (pkh 10..<13), (comma 13..<14), (wpkh 14..<18), (comma 18..<19), (combo 19..<24), (comma 24..<25), (multi 25..<30), (comma 30..<31), (sortedmulti 31..<42), (comma 42..<43), (tr 43..<45), (comma 45..<46), (addr 46..<50), (comma 50..<51), (raw 51..<54)")
    }
    
    func testLexAddress() {
        try XCTAssertEqual(DescriptorLexer.debugLex("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"), "(address 0..<34)")
        try XCTAssertEqual(DescriptorLexer.debugLex("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"), "(address 0..<34)")
        try XCTAssertEqual(DescriptorLexer.debugLex("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "(address 0..<42)")
    }
    
    func testLexData() {
        try XCTAssertEqual(DescriptorLexer.debugLex("00112233445566778899aabbccddeeff"), "(data 0..<32)")
    }
    
    // describes a P2PK output with the specified public key.
    let desc1 = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    
    // describes a P2PKH output with the specified public key.
    let desc2 = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
    
    // describes a P2WPKH output with the specified public key.
    let desc3 = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
    
    // describes a P2SH-P2WPKH output with the specified public key.
    let desc4 = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
    
    // describes any P2PK, P2PKH, P2WPKH, or P2SH-P2WPKH output with the specified public key.
    let desc5 = "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    
    // describes an (overly complicated) P2SH-P2WSH-P2PKH output with the specified public key.
    let desc6 = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"
    
    // describes a bare 1-of-2 multisig output with keys in the specified order.
    let desc7 = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
    
    // describes a P2SH 2-of-2 multisig output with keys in the specified order.
    let desc8 = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))"
    
    // describes a P2SH 2-of-2 multisig output with keys sorted lexicographically in the resulting redeemScript.
    let desc9 = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
    
    // describes a P2WSH 2-of-3 multisig output with keys in the specified order.
    let desc10 = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))"
    
    // describes a P2SH-P2WSH 1-of-3 multisig output with keys in the specified order.
    let desc11 = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))"
    
    // describes a P2PK output with the public key of the specified xpub.
    let desc12 = "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)"
    
    // describes a P2PKH output with child key 1/2 of the specified xpub.
    let desc13 = "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)"
    
    // describes a set of P2PKH outputs, but additionally specifies that the specified xpub is a child of a master with fingerprint d34db33f, and derived using path 44'/0'/0'.
    let desc14 = "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)"
    
    // describes a set of 1-of-2 P2WSH multisig outputs where the first multisig key is the 1/0/i child of the first specified xpub and the second multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range (0-1000 by default).
    let desc15 = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
    
    // describes a set of 1-of-2 P2WSH multisig outputs where one multisig key is the 1/0/i child of the first specified xpub and the other multisig key is the 0/0/i child of the second specified xpub, and i is any number in a configurable range (0-1000 by default). The order of public keys in the resulting witnessScripts is determined by the lexicographic order of the public keys at that index.
    let desc16 = "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
    
    // describes a P2TR output with the c6... x-only pubkey as internal key, and two script paths.
    let desc17 = "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})"
    
    func testLexDescriptors() {
        try XCTAssertEqual(DescriptorLexer.debugLex(desc1), "(pk 0..<2), (openParen 2..<3), (data 3..<69), (closeParen 69..<70)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc2), "(pkh 0..<3), (openParen 3..<4), (data 4..<70), (closeParen 70..<71)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc3), "(wpkh 0..<4), (openParen 4..<5), (data 5..<71), (closeParen 71..<72)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc4), "(sh 0..<2), (openParen 2..<3), (wpkh 3..<7), (openParen 7..<8), (data 8..<74), (closeParen 74..<75), (closeParen 75..<76)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc5), "(combo 0..<5), (openParen 5..<6), (data 6..<72), (closeParen 72..<73)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc6), "(sh 0..<2), (openParen 2..<3), (wsh 3..<6), (openParen 6..<7), (pkh 7..<10), (openParen 10..<11), (data 11..<77), (closeParen 77..<78), (closeParen 78..<79), (closeParen 79..<80)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc7), "(multi 0..<5), (openParen 5..<6), (int 6..<7), (comma 7..<8), (data 8..<74), (comma 74..<75), (data 75..<141), (closeParen 141..<142)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc8), "(sh 0..<2), (openParen 2..<3), (multi 3..<8), (openParen 8..<9), (int 9..<10), (comma 10..<11), (data 11..<77), (comma 77..<78), (data 78..<144), (closeParen 144..<145), (closeParen 145..<146)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc9), "(sh 0..<2), (openParen 2..<3), (sortedmulti 3..<14), (openParen 14..<15), (int 15..<16), (comma 16..<17), (data 17..<83), (comma 83..<84), (data 84..<150), (closeParen 150..<151), (closeParen 151..<152)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc10), "(wsh 0..<3), (openParen 3..<4), (multi 4..<9), (openParen 9..<10), (int 10..<11), (comma 11..<12), (data 12..<78), (comma 78..<79), (data 79..<145), (comma 145..<146), (data 146..<212), (closeParen 212..<213), (closeParen 213..<214)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc11), "(sh 0..<2), (openParen 2..<3), (wsh 3..<6), (openParen 6..<7), (multi 7..<12), (openParen 12..<13), (int 13..<14), (comma 14..<15), (data 15..<81), (comma 81..<82), (data 82..<148), (comma 148..<149), (data 149..<215), (closeParen 215..<216), (closeParen 216..<217), (closeParen 217..<218)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc12), "(pk 0..<2), (openParen 2..<3), (hdKey 3..<114), (closeParen 114..<115)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc13), "(pkh 0..<3), (openParen 3..<4), (hdKey 4..<115), (slash 115..<116), (int 116..<117), (slash 117..<118), (int 118..<119), (closeParen 119..<120)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc14), "(pkh 0..<3), (openParen 3..<4), (openBracket 4..<5), (data 5..<13), (slash 13..<14), (int 14..<16), (isHardened 16..<17), (slash 17..<18), (int 18..<19), (isHardened 19..<20), (slash 20..<21), (int 21..<22), (isHardened 22..<23), (closeBracket 23..<24), (hdKey 24..<135), (slash 135..<136), (int 136..<137), (slash 137..<138), (star 138..<139), (closeParen 139..<140)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc15), "(wsh 0..<3), (openParen 3..<4), (multi 4..<9), (openParen 9..<10), (int 10..<11), (comma 11..<12), (hdKey 12..<123), (slash 123..<124), (int 124..<125), (slash 125..<126), (int 126..<127), (slash 127..<128), (star 128..<129), (comma 129..<130), (hdKey 130..<241), (slash 241..<242), (int 242..<243), (slash 243..<244), (int 244..<245), (slash 245..<246), (star 246..<247), (closeParen 247..<248), (closeParen 248..<249)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc16), "(wsh 0..<3), (openParen 3..<4), (sortedmulti 4..<15), (openParen 15..<16), (int 16..<17), (comma 17..<18), (hdKey 18..<129), (slash 129..<130), (int 130..<131), (slash 131..<132), (int 132..<133), (slash 133..<134), (star 134..<135), (comma 135..<136), (hdKey 136..<247), (slash 247..<248), (int 248..<249), (slash 249..<250), (int 250..<251), (slash 251..<252), (star 252..<253), (closeParen 253..<254), (closeParen 254..<255)")
        try XCTAssertEqual(DescriptorLexer.debugLex(desc17), "(tr 0..<2), (openParen 2..<3), (data 3..<67), (comma 67..<68), (openBrace 68..<69), (pk 69..<71), (openParen 71..<72), (data 72..<136), (closeParen 136..<137), (comma 137..<138), (pk 138..<140), (openParen 140..<141), (data 141..<205), (closeParen 205..<206), (closeBrace 206..<207), (closeParen 207..<208)")
    }
}
