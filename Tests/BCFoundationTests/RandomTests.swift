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
        let data = deterministicRandom(entropy: "Hello, world!".utf8Data, count: 32)
        XCTAssertEqual(data, ‡"c12033c383394ccf747c273ee99c102d440d79667e0031dc5bafcb4b3dd67e8d")
    }
}
