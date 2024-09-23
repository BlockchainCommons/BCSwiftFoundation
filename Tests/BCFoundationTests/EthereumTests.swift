//
//  EthereumTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/15/21.
//

import Testing
import BCFoundation
import WolfBase
import Foundation

struct EthereumTests {
    @Test func testKeccak256() {
        func test(_ input: Data, _ expected: Data) {
            #expect(input.keccak256 == expected)
        }
        
        // Test vectors from: https://bob.nem.ninja/test-vectors.html
        test(‡"", ‡"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        test(‡"cc", ‡"eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")
        test(‡"41fb", ‡"a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2")
        test(‡"1f877c", ‡"627d7bc1491b2ab127282827b8de2d276b13d7d70fb4c5957fdf20655bc7ac30")
        test(‡"c1ecfdfc", ‡"b149e766d7612eaf7d55f74e1a4fdd63709a8115b14f61fcd22aa4abc8b8e122")
        test(‡"9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10", ‡"24dd2ee02482144f539f810d2caa8a7b75d0fa33657e47932122d273c3f6f6d1")
    }
}
