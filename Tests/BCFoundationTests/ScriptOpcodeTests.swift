//
//  ScriptOpcodeTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/3/21.
//

import Testing
@testable import BCFoundation

struct ScriptOpcodeTests {
    @Test func testConversions() {
        for op in ScriptOpcode.ops {
            let (symbol, name, rawValue) = op
            #expect(symbol.rawValue == rawValue)
            #expect(ScriptOpcode(rawValue: rawValue) == symbol)
            #expect(symbol.name == name)
            #expect(ScriptOpcode(name: name) == symbol)
        }
    }
    
    @Test func testAliases() {
        #expect(ScriptOpcode(name: "op_false") == .op_0)
        #expect(ScriptOpcode(name: "OP_TRUE") == .op_1)
        #expect(ScriptOpcode(name: "OP_NOP2") == .op_checklocktimeverify)
        #expect(ScriptOpcode(name: "OP_NOP3") == .op_checksequenceverify)
    }
}
