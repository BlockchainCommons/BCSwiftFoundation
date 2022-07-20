//
//  RandomTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/15/21.
//

import XCTest
import BCFoundation
import WolfBase

class RandomTests: XCTestCase {
    func testDeterministicRandom() {
        let data = deterministicRandom(entropy: "Hello, world!", count: 32)
        XCTAssertEqual(data, ‡"c12033c383394ccf747c273ee99c102d440d79667e0031dc5bafcb4b3dd67e8d")
    }
    
    func testGenerator() {
        let gen = DeterministicRandomNumberGenerator(‡"01020304")
        XCTAssertEqual(gen.data(count: 12).hex, "010203040102030401020304")
        XCTAssertEqual(gen.next().hex, "0102030401020304")
    }
    
    func testGenerator2() {
        var gen = DeterministicRandomNumberGenerator(entropy: "Hello, world!", count: 2000)
        let d = Data((0..<100).map { _ in UInt8.random(in: 0...255, using: &gen) })
        XCTAssertEqual(d.hex, "cf2ddc8da5d86aaf5c161b0e385d5da8a8b3ccbba19d2c9a144bb3e06b67fbe4abd48966ab21b5552ff4f3079fd4910f4711806435c9a75507e3ea76e573774774a44564e4b84f3a76584e2a57800e1415a0b8e994fac4424d4b5ecef965529ffd821bde")
    }
}
