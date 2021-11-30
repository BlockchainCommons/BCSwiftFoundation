//
//  FormatTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 10/9/21.
//

import XCTest
import BCFoundation

class FormatTests: XCTestCase {

    func testFormatSatoshi() throws {
        XCTAssertEqual(formatBTC(123_12345678), "123.12345678")
        XCTAssertEqual(formatBTC(1), "0.00000001")
        XCTAssertEqual(formatBTC(0), "0.0")
        XCTAssertEqual(formatBTC(1_00000000), "1.0")
        XCTAssertEqual(formatBTC(123_00000000), "123.0")
        XCTAssertEqual(formatBTC(123_45000000), "123.45")
        
        let sat: Satoshi = 123_12345678
        XCTAssertEqual(sat.btcFormat, "123.12345678")
    }
}
