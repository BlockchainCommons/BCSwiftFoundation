//
//  ScriptOpcode.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/3/21.
//

import Foundation
import WolfBase

public enum ScriptOpcode: UInt8, Equatable {
    // See: https://en.bitcoin.it/wiki/Script
    
    // push value
    case op_0 = 0x00
//    case op_false = 0x00
    case op_pushdata1 = 0x4c
    case op_pushdata2 = 0x4d
    case op_pushdata4 = 0x4e
    case op_1negate = 0x4f
    case op_reserved = 0x50
    case op_1 = 0x51
//    case op_true = 0x51
    case op_2 = 0x52
    case op_3 = 0x53
    case op_4 = 0x54
    case op_5 = 0x55
    case op_6 = 0x56
    case op_7 = 0x57
    case op_8 = 0x58
    case op_9 = 0x59
    case op_10 = 0x5a
    case op_11 = 0x5b
    case op_12 = 0x5c
    case op_13 = 0x5d
    case op_14 = 0x5e
    case op_15 = 0x5f
    case op_16 = 0x60

    // control
    case op_nop = 0x61
    case op_ver = 0x62
    case op_if = 0x63
    case op_notif = 0x64
    case op_verif = 0x65
    case op_vernotif = 0x66
    case op_else = 0x67
    case op_endif = 0x68
    case op_verify = 0x69
    case op_return = 0x6a

    // stack ops
    case op_toaltstack = 0x6b
    case op_fromaltstack = 0x6c
    case op_2drop = 0x6d
    case op_2dup = 0x6e
    case op_3dup = 0x6f
    case op_2over = 0x70
    case op_2rot = 0x71
    case op_2swap = 0x72
    case op_ifdup = 0x73
    case op_depth = 0x74
    case op_drop = 0x75
    case op_dup = 0x76
    case op_nip = 0x77
    case op_over = 0x78
    case op_pick = 0x79
    case op_roll = 0x7a
    case op_rot = 0x7b
    case op_swap = 0x7c
    case op_tuck = 0x7d

    // splice ops
    case op_cat = 0x7e      // Disabled.
    case op_substr = 0x7f   // Disabled.
    case op_left = 0x80     // Disabled.
    case op_right = 0x81    // Disabled.
    case op_size = 0x82

    // bit logic
    case op_invert = 0x83   // Disabled.
    case op_and = 0x84      // Disabled.
    case op_or = 0x85       // Disabled.
    case op_xor = 0x86      // Disabled.
    case op_equal = 0x87
    case op_equalverify = 0x88
    
    case op_reserved1 = 0x89
    case op_reserved2 = 0x8a

    // numeric
    case op_1add = 0x8b
    case op_1sub = 0x8c
    case op_2mul = 0x8d     // Disabled.
    case op_2div = 0x8e     // Disabled.
    case op_negate = 0x8f
    case op_abs = 0x90
    case op_not = 0x91
    case op_0notequal = 0x92

    case op_add = 0x93
    case op_sub = 0x94
    case op_mul = 0x95      // Disabled.
    case op_div = 0x96      // Disabled.
    case op_mod = 0x97      // Disabled.
    case op_lshift = 0x98   // Disabled.
    case op_rshift = 0x99   // Disabled.

    case op_booland = 0x9a
    case op_boolor = 0x9b
    case op_numequal = 0x9c
    case op_numequalverify = 0x9d
    case op_numnotequal = 0x9e
    case op_lessthan = 0x9f
    case op_greaterthan = 0xa0
    case op_lessthanorequal = 0xa1
    case op_greaterthanorequal = 0xa2
    case op_min = 0xa3
    case op_max = 0xa4

    case op_within = 0xa5

    // crypto
    case op_ripemd160 = 0xa6
    case op_sha1 = 0xa7
    case op_sha256 = 0xa8
    case op_hash160 = 0xa9
    case op_hash256 = 0xaa
    case op_codeseparator = 0xab
    case op_checksig = 0xac
    case op_checksigverify = 0xad
    case op_checkmultisig = 0xae
    case op_checkmultisigverify = 0xaf

    // expansion
    case op_nop1 = 0xb0
    case op_checklocktimeverify = 0xb1
    // case op_nop2 = 0xb1
    case op_checksequenceverify = 0xb2
    // case op_nop3 = 0xb2
    case op_nop4 = 0xb3
    case op_nop5 = 0xb4
    case op_nop6 = 0xb5
    case op_nop7 = 0xb6
    case op_nop8 = 0xb7
    case op_nop9 = 0xb8
    case op_nop10 = 0xb9

    // opcode added by bip 342 (tapscript)
    case op_checksigadd = 0xba

    case op_invalidopcode = 0xff
}

extension ScriptOpcode {
    public init?(int i: Int) {
        guard (0...16).contains(i) else {
            return nil
        }
        switch i {
        case 0:
            self = .op_0
        default:
            self = ScriptOpcode(rawValue: 0x50 + UInt8(i))!
        }
    }
}

extension ScriptOpcode {
    public var intValue: Int? {
        guard (0x51...0x60).contains(rawValue) else {
            return nil
        }
        return Int(rawValue - 0x50)
    }
}

extension ScriptOpcode: CustomStringConvertible {
    public var description: String {
        name†
    }
}

extension ScriptOpcode {
    public init?(name: String) {
        guard
            let rawValue = Self.rawValueForName[name.uppercased()],
            let opcode = ScriptOpcode(rawValue: rawValue)
        else {
            return nil
        }
        self = opcode
    }
    
    public var name: String? {
        return Self.nameForRawValue[rawValue]
    }
    
    private static let rawValueForName: [String: UInt8] = {
        var result: [String: UInt8] = [:]
        
        for (_, name, rawValue) in ops {
            assert(result[name] == nil)
            result[name] = rawValue
        }
        
        result["OP_FALSE"] = 0x00
        result["OP_TRUE"] = 0x51
        result["OP_NOP2"] = 0xb1
        result["OP_NOP3"] = 0xb2
        
        return result
    }()
    
    private static let nameForRawValue: [UInt8: String] = {
        var result: [UInt8: String] = [:]
        
        for (_, name, rawValue) in ops {
            assert(result[rawValue] == nil)
            result[rawValue] = name
        }
        
        return result
    }()
    
    static let ops: [(ScriptOpcode, String, UInt8)] = [
        // case op_false = 0x00
        (.op_0,         "OP_0",         0x00),
        (.op_pushdata1, "OP_PUSHDATA1", 0x4c),
        (.op_pushdata2, "OP_PUSHDATA2", 0x4d),
        (.op_pushdata4, "OP_PUSHDATA4", 0x4e),
        (.op_1negate,   "OP_1NEGATE",   0x4f),
        (.op_reserved,  "OP_RESERVED",  0x50),
        // case op_true = 0x51
        (.op_1,         "OP_1",         0x51),
        (.op_2,         "OP_2",         0x52),
        (.op_3,         "OP_3",         0x53),
        (.op_4,         "OP_4",         0x54),
        (.op_5,         "OP_5",         0x55),
        (.op_6,         "OP_6",         0x56),
        (.op_7,         "OP_7",         0x57),
        (.op_8,         "OP_8",         0x58),
        (.op_9,         "OP_9",         0x59),
        (.op_10,        "OP_10",        0x5a),
        (.op_11,        "OP_11",        0x5b),
        (.op_12,        "OP_12",        0x5c),
        (.op_13,        "OP_13",        0x5d),
        (.op_14,        "OP_14",        0x5e),
        (.op_15,        "OP_15",        0x5f),
        (.op_16,        "OP_16",        0x60),

        // control
        (.op_nop,       "OP_NOP",       0x61),
        (.op_ver,       "OP_VER",       0x62),
        (.op_if,        "OP_IF",        0x63),
        (.op_notif,     "OP_NOTIF",     0x64),
        (.op_verif,     "OP_VERIF",     0x65),
        (.op_vernotif,  "OP_VERNOTIF",  0x66),
        (.op_else,      "OP_ELSE",      0x67),
        (.op_endif,     "OP_ENDIF",     0x68),
        (.op_verify,    "OP_VERIFY",    0x69),
        (.op_return,    "OP_RETURN",    0x6a),

        // stack ops
        (.op_toaltstack,    "OP_TOALTSTACK",    0x6b),
        (.op_fromaltstack,  "OP_FROMALTSTACK",  0x6c),
        (.op_2drop,         "OP_2DROP",         0x6d),
        (.op_2dup,          "OP_2DUP",          0x6e),
        (.op_3dup,          "OP_3DUP",          0x6f),
        (.op_2over,         "OP_2OVER",         0x70),
        (.op_2rot,          "OP_2ROT",          0x71),
        (.op_2swap,         "OP_2SWAP",         0x72),
        (.op_ifdup,         "OP_IFDUP",         0x73),
        (.op_depth,         "OP_DEPTH",         0x74),
        (.op_drop,          "OP_DROP",          0x75),
        (.op_dup,           "OP_DUP",           0x76),
        (.op_nip,           "OP_NIP",           0x77),
        (.op_over,          "OP_OVER",          0x78),
        (.op_pick,          "OP_PICK",          0x79),
        (.op_roll,          "OP_ROLL",          0x7a),
        (.op_rot,           "OP_ROT",           0x7b),
        (.op_swap,          "OP_SWAP",          0x7c),
        (.op_tuck,          "OP_TUCK",          0x7d),

        // splice ops
        (.op_cat,       "OP_CAT",       0x7e),
        (.op_substr,    "OP_SUBSTR",    0x7f),
        (.op_left,      "OP_LEFT",      0x80),
        (.op_right,     "OP_RIGHT",     0x81),
        (.op_size,      "OP_SIZE",      0x82),

        // bit logic
        (.op_invert,        "OP_INVERT",        0x83),
        (.op_and,           "OP_AND",           0x84),
        (.op_or,            "OP_OR",            0x85),
        (.op_xor,           "OP_XOR",           0x86),
        (.op_equal,         "OP_EQUAL",         0x87),
        (.op_equalverify,   "OP_EQUALVERIFY",   0x88),
        (.op_reserved1,     "OP_RESERVED1",     0x89),
        (.op_reserved2,     "OP_RESERVED2",     0x8a),

        // numeric
        (.op_1add,                  "OP_1ADD",      0x8b),
        (.op_1sub,                  "OP_1SUB",      0x8c),
        (.op_2mul,                  "OP_2MUL",      0x8d),
        (.op_2div,                  "OP_2DIV",      0x8e),
        (.op_negate,                "OP_NEGATE",    0x8f),
        (.op_abs,                   "OP_ABS",       0x90),
        (.op_not,                   "OP_NOT",       0x91),
        (.op_0notequal,             "OP_0NOTEQUAL", 0x92),

        (.op_add,                   "OP_ADD",       0x93),
        (.op_sub,                   "OP_SUB",       0x94),
        (.op_mul,                   "OP_MUL",       0x95),
        (.op_div,                   "OP_DIV",       0x96),
        (.op_mod,                   "OP_MOD",       0x97),
        (.op_lshift,                "OP_LSHIFT",    0x98),
        (.op_rshift,                "OP_RSHIFT",    0x99),

        (.op_booland,               "OP_BOOLAND",               0x9a),
        (.op_boolor,                "OP_BOOLOR",                0x9b),
        (.op_numequal,              "OP_NUMEQUAL",              0x9c),
        (.op_numequalverify,        "OP_NUMEQUALVERIFY",        0x9d),
        (.op_numnotequal,           "OP_NUMNOTEQUAL",           0x9e),
        (.op_lessthan,              "OP_LESSTHAN",              0x9f),
        (.op_greaterthan,           "OP_GREATERTHAN",           0xa0),
        (.op_lessthanorequal,       "OP_LESSTHANOREQUAL",       0xa1),
        (.op_greaterthanorequal,    "OP_GREATERTHANOREQUAL",    0xa2),
        (.op_min,                   "OP_MIN",                   0xa3),
        (.op_max,                   "OP_MAX",                   0xa4),

        (.op_within,                "OP_WITHIN",    0xa5),

        // crypto
        (.op_ripemd160,             "OP_RIPEMD160",             0xa6),
        (.op_sha1,                  "OP_SHA1",                  0xa7),
        (.op_sha256,                "OP_SHA256",                0xa8),
        (.op_hash160,               "OP_HASH160",               0xa9),
        (.op_hash256,               "OP_HASH256",               0xaa),
        (.op_codeseparator,         "OP_CODESEPARATOR",         0xab),
        (.op_checksig,              "OP_CHECKSIG",              0xac),
        (.op_checksigverify,        "OP_CHECKSIGVERIFY",        0xad),
        (.op_checkmultisig,         "OP_CHECKMULTISIG",         0xae),
        (.op_checkmultisigverify,   "OP_CHECKMULTISIGVERIFY",   0xaf),

        // expansion
        (.op_nop1,                  "OP_NOP1",                  0xb0),
        (.op_checklocktimeverify,   "OP_CHECKLOCKTIMEVERIFY",   0xb1),
        // case op_nop2 = 0xb1
        (.op_checksequenceverify,   "OP_CHECKSEQUENCEVERIFY",   0xb2),
        // case op_nop3 = 0xb2
        (.op_nop4,                  "OP_NOP4",                  0xb3),
        (.op_nop5,                  "OP_NOP5",                  0xb4),
        (.op_nop6,                  "OP_NOP6",                  0xb5),
        (.op_nop7,                  "OP_NOP7",                  0xb6),
        (.op_nop8,                  "OP_NOP8",                  0xb7),
        (.op_nop9,                  "OP_NOP9",                  0xb8),
        (.op_nop10,                 "OP_NOP10",                 0xb9),

        // opcode added by bip 342 (tapscript)
        (.op_checksigadd,   "OP_CHECKSIGADD",   0xba),

        (.op_invalidopcode, "OP_INVALIDOPCODE", 0xff)
    ]
}

