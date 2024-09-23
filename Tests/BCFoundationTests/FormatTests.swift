//
//  FormatTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 10/9/21.
//

import Testing
import BCFoundation

struct FormatTests {
    @Test func testFormatSatoshi() throws {
        #expect(formatBTC(123_12345678) == "123.12345678")
        #expect(formatBTC(1) == "0.00000001")
        #expect(formatBTC(0) == "0.0")
        #expect(formatBTC(1_00000000) == "1.0")
        #expect(formatBTC(123_00000000) == "123.0")
        #expect(formatBTC(123_45000000) == "123.45")
        
        let sat: Satoshi = 123_12345678
        #expect(sat.btcFormat == "123.12345678")
    }
}
