//
//  File.swift
//  
//
//  Created by Wolf McNally on 3/6/22.
//

import Foundation

// Descriptor checksums are described here: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
// Based on the code here: https://github.com/ccapo/BitcoinDescriptorChecksum

fileprivate func polyMod(_ c: UInt64, _ val: Int) -> UInt64 {
    let c0 = UInt8(c >> 35)
    var c = ((c & UInt64(0x7ffffffff)) << 5) ^ UInt64(val);
    if c0 & 1 != 0 { c ^= 0xf5dee51989 }
    if c0 & 2 != 0 { c ^= 0xa9fdca3312 }
    if c0 & 4 != 0 { c ^= 0x1bab10e32d }
    if c0 & 8 != 0 { c ^= 0x3706b1677a }
    if c0 & 16 != 0 { c ^= 0x644d626ffd }
    return c
}

/** A character set designed such that:
 *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
 *  - Case errors cause an offset that's a multiple of 32.
 *  - As many alphabetic characters are in the same group (while following the above restrictions).
 *
 * If p(x) gives the position of a character c in this character set, every group of 3 characters
 * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
 * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
 * affect a single symbol.
 *
 * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
 * the position within the groups.
 */
fileprivate let inputCharset = Array("0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ")

/// The character set for the checksum itself (same as bech32).
let descriptorChecksumCharset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

func descriptorChecksum(_ str: String) -> String? {
    var c: UInt64 = 1
    var cls = 0
    var clsCount = 0
    for char in str {
        guard let pos = inputCharset.firstIndex(of: char) else {
            return nil
        }
        c = polyMod(c, pos & 31) // Emit a symbol for the position inside the group, for every character.
        cls = cls * 3 + (pos >> 5) // Accumulate the group numbers
        clsCount += 1
        if clsCount == 3 {
            // Emit an extra symbol representing the group numbers, for every 3 characters.
            c = polyMod(c, cls)
            cls = 0
            clsCount = 0
        }
    }
    if clsCount > 0 {
        c = polyMod(c, cls)
    }
    for _ in 0..<8 {
        c = polyMod(c, 0) // Shift further to determine the checksum.
    }
    c ^= 1 // Prevent appending zeroes from not affecting the checksum.
    
    return String((0..<8).map { descriptorChecksumCharset[Int((c >> (5 * (7 - $0))) & 31)] })
}
