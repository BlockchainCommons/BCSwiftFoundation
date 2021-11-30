//
//  ScriptOpcodeTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/3/21.
//

import XCTest
@testable import BCFoundation

class ScriptOpcodeTests: XCTestCase {
    func testConversions() {
        for op in ScriptOpcode.ops {
            let (symbol, name, rawValue) = op
            XCTAssertEqual(symbol.rawValue, rawValue)
            XCTAssertEqual(ScriptOpcode(rawValue: rawValue), symbol)
            XCTAssertEqual(symbol.name, name)
            XCTAssertEqual(ScriptOpcode(name: name), symbol)
        }
    }
    
    func testAliases() {
        XCTAssertEqual(ScriptOpcode(name: "op_false"), .op_0)
        XCTAssertEqual(ScriptOpcode(name: "OP_TRUE"), .op_1)
        XCTAssertEqual(ScriptOpcode(name: "OP_NOP2"), .op_checklocktimeverify)
        XCTAssertEqual(ScriptOpcode(name: "OP_NOP3"), .op_checksequenceverify)
    }
}
