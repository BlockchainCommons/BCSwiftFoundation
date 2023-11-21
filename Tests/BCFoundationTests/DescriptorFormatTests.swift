//
//  DescriptorParserTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/1/21.
//

import XCTest
import BCFoundation
import WolfBase

class DescriptorFormatTests: XCTestCase {
    func testParseMultikey() throws {
        let source = "wsh(sortedmulti(2,[dc567276/48'/0'/0'/2']xpub6DiYrfRwNnjeX4vHsWMajJVFKrbEEnu8gAW9vDuQzgTWEsEHE16sGWeXXUV1LBWQE1yCTmeprSNcqZ3W74hqVdgDbtYHUv3eM4W2TEUhpan/<0;1>/*,[f245ae38/48'/0'/0'/2']xpub6DnT4E1fT8VxuAZW29avMjr5i99aYTHBp9d7fiLnpL5t4JEprQqPMbTw7k7rh5tZZ2F5g8PJpssqrZoebzBChaiJrmEvWwUTEMAbHsY39Ge/<0;1>/*,[c5d87297/48'/0'/0'/2']xpub6DjrnfAyuonMaboEb3ZQZzhQ2ZEgaKV2r64BFmqymZqJqviLTe1JzMr2X2RfQF892RH7MyYUbcy77R7pPu1P71xoj8cDUMNhAMGYzKR4noZ/<0;1>/*))"
        var desc = try OutputDescriptor(source)
        desc.name = "Satoshi's Stash"
        
        let cbor = desc.cbor
//        print(cbor.diagnostic())

        let desc2 = try OutputDescriptor(cbor: cbor)
        XCTAssertEqual(desc, desc2)
    }
}
