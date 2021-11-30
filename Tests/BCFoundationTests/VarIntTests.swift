//
//  VarIntTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/9/21.
//

import XCTest
import BCFoundation
import WolfBase

class VarIntTests: XCTestCase {
    func testExample() throws {
        func test(_ i: Int, _ hex: String) {
            let v = VarInt(i)!
            let h = v.serialized.hex
            XCTAssertEqual(h, hex)
            let d = Data(hex: h)!
            let v2 = VarInt(d)!
            XCTAssertEqual(v, v2)
        }
        test(0x12, "12")
        test(0x1234, "fd3412")
        test(0x12345678, "fe78563412")
        test(0x123456789abcdef0, "fff0debc9a78563412")
    }
}
