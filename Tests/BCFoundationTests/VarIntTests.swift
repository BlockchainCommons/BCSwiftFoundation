//
//  VarIntTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/9/21.
//

import Testing
import BCFoundation
import WolfBase
import Foundation

struct VarIntTests {
    @Test func testExample() throws {
        func test(_ i: Int, _ hex: String) {
            let v = VarInt(i)!
            let h = v.serialized.hex
            #expect(h == hex)
            let d = Data(hex: h)!
            let v2 = VarInt(d)!
            #expect(v == v2)
        }
        test(0x12, "12")
        test(0x1234, "fd3412")
        test(0x12345678, "fe78563412")
        test(0x123456789abcdef0, "fff0debc9a78563412")
    }
}
