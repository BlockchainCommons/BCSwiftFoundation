//
//  DescriptorParserTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/1/21.
//

import XCTest
import BCFoundation
import WolfBase

class DescriptorParserTests: XCTestCase {
    static let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
    static let hdKey = try! HDKey(base58: tprv)
    static let ecPub = hdKey.ecPublicKey.hex
    static let ecPubUncompressed = hdKey.ecPublicKey.uncompressedPublicKey.hex
    static let wif = hdKey.ecPrivateKey!.wif
    static let tpub = hdKey.base58PublicKey!
    
    override class func setUp() {
        super.setUp()
        addKnownTags()
    }
    
    func checkRoundTrip(
        source: String,
        scriptPubKey: String? = nil,
        cborHex: String,
        diag: String,
        name: String? = nil
    ) -> Bool {
        var desc = try! OutputDescriptor(source)
        
        if let name {
            desc.name = name
        }
        
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.source, source)
        
        if let scriptPubKey {
            XCTAssertEqual(desc.scriptPubKey()†, scriptPubKey)
        }
        
        let reDesc = try! OutputDescriptor(cbor: desc.cbor)
        if desc != reDesc {
            print("desc:")
            print(desc)
            print(desc.cborData.hex)
            print(desc.cbor.diagnostic())

            print("reDesc:")
            print(reDesc)
            print(reDesc.cborData.hex)
            print(reDesc.cbor.diagnostic())

            return false
        }
        
        let hex = desc.cbor.hex
        if !cborHex.isEmpty {
            if hex != cborHex {
                print(hex)
                return false
            }
        } else {
            print(hex)
        }
        
        let diagnostic = desc.taggedCBOR.diagnostic()
        if !diag.isEmpty {
            if diagnostic != diag {
                print(diagnostic)
                return false
            }
        } else {
            print(diagnostic)
        }
        return true
    }

    func testRaw() throws {
        let source = "raw(76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac)"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.ur†, "ur:output-descriptor/oeadiojphsktdefzdydtaolyhdcfkoptbbrnykoeytonimmwpkpadkhkyldrtatklkwnnskgrnlopskovafstb")
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a20167726177284030290281581976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "raw(@0)",
                  2:
                  [
                     h'76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac'
                  ]
               }
            )
            """
        ))
    }
    
    func testPK1() throws {
        let source = "pk(\(Self.ecPub))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]",
            cborHex: "d99d74a20166706b284030290281d99d72a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pk(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPK2() throws {
        let source = "pk(\(Self.ecPubUncompressed))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pk:[04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG]",
            cborHex: "d99d74a20166706b284030290281d99d72a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pk(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPK3() throws {
        let source = "pk(\(Self.wif))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]",
            cborHex: "d99d74a20166706b284030290281d99d72a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pk(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           2:
                           true,
                           3:
                           h'347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPK4() throws {
        let source = "pk(\(Self.tprv))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]",
            cborHex: "d99d74a20166706b284030290281d99d6fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pk(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           2:
                           true,
                           3:
                           h'00347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPK5() throws {
        let source = "pk(\(Self.tpub))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]",
            cborHex: "d99d74a20166706b284030290281d99d6fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pk(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCosigner1() throws {
        let source = "cosigner(\(Self.ecPub))"
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016c636f7369676e6572284030290281d99d72a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "cosigner(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCosigner2() throws {
        let source = "cosigner(\(Self.ecPubUncompressed))"
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016c636f7369676e6572284030290281d99d72a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "cosigner(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCosigner3() throws {
        let source = "cosigner(\(Self.wif))"
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016c636f7369676e6572284030290281d99d72a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "cosigner(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           2:
                           true,
                           3:
                           h'347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCosigner4() throws {
        let source = "cosigner(\(Self.tprv))"
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016c636f7369676e6572284030290281d99d6fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "cosigner(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           2:
                           true,
                           3:
                           h'00347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCosigner5() throws {
        let source = "cosigner(\(Self.tpub))"
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016c636f7369676e6572284030290281d99d6fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "cosigner(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPKH1() throws {
        let source = "pkh(\(Self.ecPub))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a20167706b68284030290281d99d72a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }

    func testPKH2() throws {
        let source = "pkh(\(Self.ecPubUncompressed))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a20167706b68284030290281d99d72a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }

    func testPKH3() throws {
        let source = "pkh(\(Self.wif))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a20167706b68284030290281d99d72a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           2:
                           true,
                           3:
                           h'347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }

    func testPKH4() throws {
        let source = "pkh(\(Self.tprv))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a20167706b68284030290281d99d6fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           2:
                           true,
                           3:
                           h'00347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }

    func testPKH5() throws {
        let source = "pkh(\(Self.tpub))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a20167706b68284030290281d99d6fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testWPKH1() throws {
        let source = "wpkh(\(Self.ecPub))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]",
            cborHex: "d99d74a2016877706b68284030290281d99d72a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testWPKH2() throws {
        let source = "wpkh(\(Self.ecPubUncompressed))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wpkh:[OP_0 335f3a94aeed3518f0baedc04330945e3dd0744b]",
            cborHex: "d99d74a2016877706b68284030290281d99d72a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testWPKH3() throws {
        let source = "wpkh(\(Self.wif))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]",
            cborHex: "d99d74a2016877706b68284030290281d99d72a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           2:
                           true,
                           3:
                           h'347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testWPKH4() throws {
        let source = "wpkh(\(Self.tprv))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]",
            cborHex: "d99d74a2016877706b68284030290281d99d6fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           2:
                           true,
                           3:
                           h'00347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testWPKH5() throws {
        let source = "wpkh(\(Self.tpub))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]",
            cborHex: "d99d74a2016877706b68284030290281d99d6fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d99d71a1020106d99d70a3018200f5021a4efd3ded0303081ae0c98d67",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2',
                           4:
                           h'5b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb3',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [0, true],
                                 2:
                                 1325219309,
                                 3:
                                 3
                              }
                           ),
                           8:
                           3771305319
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testMulti1() throws {
        let source = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "multi:[OP_1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc OP_2 OP_CHECKMULTISIG]",
            cborHex: "d99d74a2016e6d756c746928312c40302c4031290282d99d72a1035821022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d99d72a1035821025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "multi(1,@0,@1)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testMulti2() throws {
        let source = "multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "multi:[OP_2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a OP_3 OP_CHECKMULTISIG]",
            cborHex: "d99d74a201716d756c746928322c40302c40312c4032290283d99d72a103582103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7d99d72a103582103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbd99d72a103582103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "multi(2,@0,@1,@2)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func sortedMultiTest(threshold: Int, keys: [String], script: String, address: String, cborHex: String, diag: String) throws {
        let k = keys.joined(separator: ",")
        let source = "sortedmulti(\(threshold),\(k))"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.scriptPubKey()?.hex, script)
        let address = Bitcoin.Address(scriptPubKey: desc.scriptPubKey()!, network: .mainnet)!.string
        XCTAssertEqual(address, address)
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: cborHex,
            diag: diag
        ))
    }
    
    // https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki#test-vectors
    func testSortedMulti1() throws {
        try sortedMultiTest(
            threshold: 2,
            keys: [
                "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"
            ],
            script: "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
            address: "bc1qknwt9mhqpd7hrjrvpqz57zjqk28xlp2h90te6v22en0m3uctnams3pq5ce",
            cborHex: "d99d74a20174736f727465646d756c746928322c40302c4031290282d99d72a103582102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8d99d72a103582102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sortedmulti(2,@0,@1)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f'
                        }
                     )
                  ]
               }
            )
            """
        )
    }
    
    func testSortedMulti2() throws {
        try sortedMultiTest(
            threshold: 2,
            keys: [
                "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404"
            ],
            script: "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed021027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e772102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
            address: "bc1qud6dmdcc27eg8s5hsy6a075gs49w65l6xtc4cplp6m2d4ggh43wqew2vqs",
            cborHex: "d99d74a20177736f727465646d756c746928322c40302c40312c4032290283d99d72a103582102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0d99d72a1035821027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77d99d72a103582102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sortedmulti(2,@0,@1,@2)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404'
                        }
                     )
                  ]
               }
            )
            """
        )
    }
    
    func testSortedMulti3() throws {
        try sortedMultiTest(
            threshold: 2,
            keys: [
                "030000000000000000000000000000000000004141414141414141414141414141",
                "020000000000000000000000000000000000004141414141414141414141414141",
                "020000000000000000000000000000000000004141414141414141414141414140",
                "030000000000000000000000000000000000004141414141414141414141414140"
            ],
            script: "522102000000000000000000000000000000000000414141414141414141414141414021020000000000000000000000000000000000004141414141414141414141414141210300000000000000000000000000000000000041414141414141414141414141402103000000000000000000000000000000000000414141414141414141414141414154ae",
            address: "bc1q43l9uw4l5q3d3eltdvf785atcpfys8wad6z4rv6mltnzrzasq0jqp0lwze",
            cborHex: "d99d74a201781a736f727465646d756c746928322c40302c40312c40322c4033290284d99d72a1035821030000000000000000000000000000000000004141414141414141414141414141d99d72a1035821020000000000000000000000000000000000004141414141414141414141414141d99d72a1035821020000000000000000000000000000000000004141414141414141414141414140d99d72a1035821030000000000000000000000000000000000004141414141414141414141414140",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sortedmulti(2,@0,@1,@2,@3)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'030000000000000000000000000000000000004141414141414141414141414141'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'020000000000000000000000000000000000004141414141414141414141414141'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'020000000000000000000000000000000000004141414141414141414141414140'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'030000000000000000000000000000000000004141414141414141414141414140'
                        }
                     )
                  ]
               }
            )
            """
        )
    }
    
    func testSortedMulti4() throws {
        try sortedMultiTest(
            threshold: 2,
            keys: [
                "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"
            ],
            script: "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc1821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
            address: "bc1q0uyls9kc4acv9ntqw6u096t53jlld4frp4rscrf8fruddhu62p6sy9507s",
            cborHex: "d99d74a20177736f727465646d756c746928322c40302c40312c4032290283d99d72a1035821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014dad99d72a103582103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9d99d72a1035821021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sortedmulti(2,@0,@1,@2)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18'
                        }
                     )
                  ]
               }
            )
            """
        )
    }
    
    func testSortedMulti5() throws {
        let source = "sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH)"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.scriptPubKey()?.asm, "OP_1 02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea 03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7 OP_2 OP_CHECKMULTISIG")
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20174736f727465646d756c746928312c40302c4031290282d99d6fa303582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d99d70a30180021abd16bee50300d99d6fa403582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d99d70a30180021a5a61ff8e0301081abd16bee5",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sortedmulti(1,@0,@1)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7',
                           4:
                           h'60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 3172384485,
                                 3:
                                 0
                              }
                           )
                        }
                     ),
                     40303(   / hdkey /
                        {
                           3:
                           h'02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea',
                           4:
                           h'f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 1516371854,
                                 3:
                                 1
                              }
                           ),
                           8:
                           3172384485
                        }
                     )
                  ]
               }
            )
            """
        ))
    }

    func testAddr1() throws {
        let addressp2pkh = Bitcoin.Address(hdKey: Self.hdKey, type: .payToPubKeyHash).string
        XCTAssertEqual(addressp2pkh, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
        
        let source = "addr(\(addressp2pkh))"
        let p2shp2wpkh = Bitcoin.Address(hdKey: Self.hdKey, type: .payToScriptHashPayToWitnessPubKeyHash).string
        XCTAssertEqual(p2shp2wpkh, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]",
            cborHex: "d99d74a2016861646472284030290281d99d73a301d99d71a10201020003544efd3ded47d967e4122982422c9d84db60503972",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "addr(@0)",
                  2:
                  [
                     40307(   / address /
                        {
                           1:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           2:
                           0,
                           3:
                           h'4efd3ded47d967e4122982422c9d84db60503972'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testAddr2() throws {
        let p2shp2wpkh = Bitcoin.Address(hdKey: Self.hdKey, type: .payToScriptHashPayToWitnessPubKeyHash).string
        let source = "addr(\(p2shp2wpkh))"
        let p2wpkh = Bitcoin.Address(hdKey: Self.hdKey, type: .payToWitnessPubKeyHash).string
        XCTAssertEqual(p2wpkh, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "sh:[OP_HASH160 8fb371a0195598d96e634b9eddb645fa1f128e11 OP_EQUAL]",
            cborHex: "d99d74a2016861646472284030290281d99d73a301d99d71a10201020103548fb371a0195598d96e634b9eddb645fa1f128e11",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "addr(@0)",
                  2:
                  [
                     40307(   / address /
                        {
                           1:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           2:
                           1,
                           3:
                           h'8fb371a0195598d96e634b9eddb645fa1f128e11'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testAddr3() throws {
        let p2wpkh = Bitcoin.Address(hdKey: Self.hdKey, type: .payToWitnessPubKeyHash).string
        let source = "addr(\(p2wpkh))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]",
            cborHex: "d99d74a2016861646472284030290281d99d73a301d99d71a10201020203544efd3ded47d967e4122982422c9d84db60503972",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "addr(@0)",
                  2:
                  [
                     40307(   / address /
                        {
                           1:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           2:
                           2,
                           3:
                           h'4efd3ded47d967e4122982422c9d84db60503972'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testHDKey1() throws {
        let source = "pkh([d34db33f/44'/0'/0']xpub6CY2xt3mvQejPFUw26CychtL4GMq1yp41aMW2U27mvThqefpZYwXpGscV26JuVj13Fpg4kgSENheUSbTqm5f8z25zrhXpPVss5zWeMGnAKR/1/*)"
        let desc = try OutputDescriptor(source)
        XCTAssertTrue(desc.requiresAddressIndex)
        XCTAssertNil(desc.scriptPubKey()) // requires wildcard
        XCTAssertEqual(desc.scriptPubKey(addressIndex: 0)†, "pkh:[OP_DUP OP_HASH160 2a05c214617c9b0434c92d0583200a85ef61818f OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(addressIndex: 1)†, "pkh:[OP_DUP OP_HASH160 49b2f81eea1ecb5bc97d78f2d8f89d9c861c3cf2 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20167706b68284030290281d99d6fa503582102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0045820637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2906d99d70a20186182cf500f500f5021ad34db33f07d99d70a1018401f480f4081a78412e3a",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0',
                           4:
                           h'637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [44, true, 0, true, 0, true],
                                 2:
                                 3545084735
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    1,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           2017537594
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testHDKey2() throws {
        // This base58 key is actually not a master key; it is a level 3 key. So here we force it to become a master key.
        let masterKey = try HDKey(base58: "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA", parent: .init(origin: .master))
        let purposePath = DerivationPath(string: "44'")!
        let purposePrivateKey = try HDKey(parent: masterKey, childDerivationPath: purposePath)
        XCTAssertEqual(purposePrivateKey.fullDescription, "[4efd3ded/44']tprv8c9mJ6Pkmf4eC93951CVmVVJBMnVPt4BoEsXVckBK4LeJ6dkPmDC1YEjLQSMGVAuUiHMbTTXYuosFLC3gdN5AjwXSjir94Tew4Pbh8V7mNM")

        let accountPath = DerivationPath(string: "0'/0'")!
        let children = DerivationPath(string: "1'/*")!
        let accountPrivateKey = try HDKey(parent: purposePrivateKey, childDerivationPath: accountPath, children: children)
        XCTAssertEqual(accountPrivateKey.fullDescription, "[4efd3ded/44'/0'/0']tprv8fTYFKEQNDoECQKCFeYrXMtHNspLL1GLv2Ept6YasB7KdAggQ8MHBuzFimBMxdMeJbUWoETLKWNUucxXmgtJyNb3uaLzCxidmAY88AwYtmX/1'/*")

        let accountPublicKey = accountPrivateKey.public
        XCTAssertEqual(accountPublicKey.fullDescription, "[4efd3ded/44'/0'/0']tpubDC9aPjGeWbUu5sLz9JDSvmYPwuLGVLTFVKqcAcatHSuiTewT2XAsNQc7tsvhcXMz216Ed28BvtnWN73aANARJFSfFdT39vPTTf28Mtbkn7D/1'/*")
        
        let source = "pkh(\(accountPublicKey.fullDescription))"
        let desc = try OutputDescriptor(source)
        XCTAssertTrue(desc.requiresAddressIndex)
        XCTAssertNil(desc.scriptPubKey(addressIndex: 0)) // requires private key.
        
        let lookup: [UInt32 : HDKey] = [
            masterKey.keyFingerprint : masterKey
        ]
        
        let fullPath = purposePath + accountPath
        XCTAssertEqual(fullPath†, "44'/0'/0'")
        
        func privateKeyProvider(key: any HDKeyProtocol) -> HDKey? {
            guard
                case let .fingerprint(originFingerprint) = key.parent.origin,
                let masterKey = lookup[originFingerprint],
                let privateKey = try? HDKey(parent: masterKey, childDerivationPath: fullPath)
            else {
                return nil
            }
            return privateKey
        }
        
        XCTAssertEqual(desc.scriptPubKey(addressIndex: 0, privateKeyProvider: privateKeyProvider)†, "pkh:[OP_DUP OP_HASH160 c3d4f598ec80d57820226529645b7805d078cab0 OP_EQUALVERIFY OP_CHECKSIG]")

        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20167706b68284030290281d99d6fa603582102b705663fa1839bc7de73fcb18038a75facb7509df15230379147011ebb343140045820d10491ab8729ef3ca5e7555f54f04605d06b01b35e379b2cdc2fcae271410a9805d99d71a1020106d99d70a20186182cf500f500f5021a4efd3ded07d99d70a1018401f580f4081a10d66527",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "pkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'02b705663fa1839bc7de73fcb18038a75facb7509df15230379147011ebb343140',
                           4:
                           h'd10491ab8729ef3ca5e7555f54f04605d06b01b35e379b2cdc2fcae271410a98',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [44, true, 0, true, 0, true],
                                 2:
                                 1325219309
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    1,
                                    true,
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           282486055
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_SH_WPKH() throws {
        let source = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "sh:[OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL]",
            cborHex: "d99d74a2016c73682877706b6828403029290281d99d72a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sh(wpkh(@0))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_WSH_PKH() throws {
        let source = "wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wsh:[OP_0 fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f]",
            cborHex: "d99d74a2016c77736828706b6828403029290281d99d72a103582102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wsh(pkh(@0))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_SH_WSH_PKH() throws {
        let source = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "sh:[OP_HASH160 55e8d5e8ee4f3604aba23c71c2684fa0a56a3a12 OP_EQUAL]",
            cborHex: "d99d74a2017073682877736828706b682840302929290281d99d72a103582102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sh(wsh(pkh(@0)))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_SH_MULTI() throws {
        let source = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "sh:[OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL]",
            cborHex: "d99d74a201727368286d756c746928322c40302c403129290282d99d72a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01d99d72a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sh(multi(2,@0,@1))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_SH_SORTEDMULTI() throws {
        let source = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "sh:[OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL]",
            cborHex: "d99d74a2017818736828736f727465646d756c746928322c40302c403129290282d99d72a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbed99d72a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sh(sortedmulti(2,@0,@1))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_WSH_MULTI() throws {
        let source = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))"
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "wsh:[OP_0 773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a]",
            cborHex: "d99d74a20176777368286d756c746928322c40302c40312c403229290283d99d72a103582103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7d99d72a103582103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbd99d72a103582103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wsh(multi(2,@0,@1,@2))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_SH_WSH_MULTI() throws {
        let source = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))"
        let desc = try OutputDescriptor(source)
        XCTAssertFalse(desc.requiresAddressIndex)
        XCTAssert(checkRoundTrip(
            source: source,
            scriptPubKey: "sh:[OP_HASH160 aec509e284f909f769bb7dda299a717c87cc97ac OP_EQUAL]",
            cborHex: "d99d74a201781a736828777368286d756c746928312c40302c40312c40322929290283d99d72a103582103f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8d99d72a103582103499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4d99d72a103582102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "sh(wsh(multi(1,@0,@1,@2)))",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4'
                        }
                     ),
                     40306(   / eckey /
                        {
                           3:
                           h'02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_WSH_MULTI_HD() throws {
        let source = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
        let desc = try OutputDescriptor(source)
        XCTAssertTrue(desc.requiresAddressIndex)
        XCTAssertEqual(desc.scriptPubKey(addressIndex: 0)†, "wsh:[OP_0 64969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b]")
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20173777368286d756c746928312c40302c403129290282d99d6fa403582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d99d70a30180021abd16bee5030007d99d70a1018601f400f480f4d99d6fa503582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d99d70a30180021a5a61ff8e030107d99d70a1018600f400f480f4081abd16bee5",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wsh(multi(1,@0,@1))",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7',
                           4:
                           h'60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 3172384485,
                                 3:
                                 0
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    1,
                                    false,
                                    0,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           )
                        }
                     ),
                     40303(   / hdkey /
                        {
                           3:
                           h'02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea',
                           4:
                           h'f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 1516371854,
                                 3:
                                 1
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    0,
                                    false,
                                    0,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           3172384485
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func test_WSH_MULTI_HD_2() throws {
        // This test vector from: https://bitcoindevkit.org/descriptors/
        let source = "wsh(multi(2,tprv8ZgxMBicQKsPePmENhT9N9yiSfTtDoC1f39P7nNmgEyCB6Nm4Qiv1muq4CykB9jtnQg2VitBrWh8PJU8LHzoGMHTrS2VKBSgAz7Ssjf9S3P/0/*,tpubDBYDcH8P2PedrEN3HxWYJJJMZEdgnrqMsjeKpPNzwe7jmGwk5M3HRdSf5vudAXwrJPfUsfvUPFooKWmz79Lh111U51RNotagXiGNeJe3i6t/1/*))"
        let desc = try OutputDescriptor(source)
        let scriptPubKey0 = desc.scriptPubKey(addressIndex: 0)!
        let scriptPubKey1 = desc.scriptPubKey(addressIndex: 1)!
        XCTAssertEqual(Bitcoin.Address(scriptPubKey: scriptPubKey0, network: .testnet)!.string, "tb1qqsat6c82fvdy73rfzye8f7nwxcz3xny7t56azl73g95mt3tmzvgs9a8vjs")
        XCTAssertEqual(Bitcoin.Address(scriptPubKey: scriptPubKey1, network: .testnet)!.string, "tb1q7sgx6gscgtau57jduend6a8l445ahpk3dt3u5zu58rx5qm27lhkqgfdjdr")
        XCTAssertEqual(desc.ur†, "ur:output-descriptor/oeadjkktjkisdejnkpjzjyindeeydwfzdydwfzehdtdtaolftantjlolaoykaxhdclaegllboslbkenbttvyfpjodywmuoylyamhiotsvlkevdnybkylkgcemdesadcarsfmaahdcxmkpanldlkoeynsfgaymhkpdrhnltsrvepezeronsdmksinchdsswmtmwldfmgduoahtantjsoyaoadamtantjootadlaaocymejpryvsaxaeattantjooyadlraewklawktantjlolaxhdclaxkpgohnfewlwpmsftotjojsmybbdaeehtgreyimbkcmdsmtaebsktceenhdvybgzcaahdcxenttsttlgmdlmnvomseyfnfxvohynbfgsfwssoftdkcmcpknuogtcpclltdekptdahtantjsoyaoadamtantjootadlaaocynsbztefeaxaoattantjooyadlradwklawkaycyryvwpkytrsmdhtde")
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20173777368286d756c746928322c40302c403129290282d99d6fa602f5035821004e7fa77f7ca0d1e1417030ebdcf7f89067d7e37ce79a0af77b1c9539011dbf3e04582098b1992f76329c460890752a6087c3e4affeb89c2e78691726c69694893e50dc05d99d71a1020106d99d70a30180021a9172bde8030007d99d70a1018400f480f4d99d6fa60358210375556045e9ec973aa370718f1425345a4b326a0a162696000f771c3658e112fd04582036d1c7d5522f8ee297323c43e25ea046ccefc93a2416227adc4d2221872875d205d99d71a1020106d99d70a30180021a9c15d345030207d99d70a1018401f480f4081abde5aaf9",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wsh(multi(2,@0,@1))",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           2:
                           true,
                           3:
                           h'004e7fa77f7ca0d1e1417030ebdcf7f89067d7e37ce79a0af77b1c9539011dbf3e',
                           4:
                           h'98b1992f76329c460890752a6087c3e4affeb89c2e78691726c69694893e50dc',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 2440216040,
                                 3:
                                 0
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    0,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           )
                        }
                     ),
                     40303(   / hdkey /
                        {
                           3:
                           h'0375556045e9ec973aa370718f1425345a4b326a0a162696000f771c3658e112fd',
                           4:
                           h'36d1c7d5522f8ee297323c43e25ea046ccefc93a2416227adc4d2221872875d2',
                           5:
                           40305(   / coin-info /
                              {2: 1}
                           ),
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 2618676037,
                                 3:
                                 2
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    1,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           3185945337
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCombo1() throws {
        // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
        // compressed
        let source = "combo(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)"
        let desc = try OutputDescriptor(source)
        XCTAssertTrue(desc.isCombo)
        XCTAssertFalse(desc.requiresAddressIndex)
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pk)†, "pk:[022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pkh)†, "pkh:[OP_DUP OP_HASH160 9652d86bedf43ad264362e6e6eba6eb764508127 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .wpkh)†, "wpkh:[OP_0 9652d86bedf43ad264362e6e6eba6eb764508127]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .sh_wpkh)†, "sh:[OP_HASH160 edcbce4e0cce791e8ddb72705133fa3566145fa6 OP_EQUAL]")
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20169636f6d626f284030290281d99d72a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "combo(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testCombo2() throws {
        // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
        // uncompressed
        let source = "combo(04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27)"
        let desc = try OutputDescriptor(source)
        XCTAssertTrue(desc.isCombo)
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pk)†, "pk:[04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pkh)†, "pkh:[OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertNil(desc.scriptPubKey(comboOutput: .wpkh))
        XCTAssertNil(desc.scriptPubKey(comboOutput: .sh_wpkh))
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20169636f6d626f284030290281d99d72a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "combo(@0)",
                  2:
                  [
                     40306(   / eckey /
                        {
                           3:
                           h'04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27'
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testChecksum() throws {
        let source = "pkh([00000000/0'/0']tprv8et1s5VnWCG3v3R6vXX5hprTpdCdcBp3jRuoDByaF9uAkCt5XjfuX52hgh63aWzCYpXNU2YyxAj78qg8PS2EuGUKE8Untk6NVe7FAG8RdLk/*')"
        let expectedChecksum = "3428vapa"
        let checksum = OutputDescriptor.checksum(source)!
        XCTAssertEqual(checksum, expectedChecksum)
        
        let sourceWithChecksum = "pkh([00000000/0'/0']tprv8et1s5VnWCG3v3R6vXX5hprTpdCdcBp3jRuoDByaF9uAkCt5XjfuX52hgh63aWzCYpXNU2YyxAj78qg8PS2EuGUKE8Untk6NVe7FAG8RdLk/*')#3428vapa"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.sourceWithChecksum, sourceWithChecksum)
        
        XCTAssertNoThrow(try OutputDescriptor.validateChecksum(sourceWithChecksum))
        
        let sourceWithBadChecksum = sourceWithChecksum.dropLast().appending("b")
        XCTAssertThrowsError(try OutputDescriptor.validateChecksum(sourceWithBadChecksum))
    }
    
    func testAddressGeneration() throws {
        let source = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
        let desc = try OutputDescriptor(source)
        let addresses = desc.addresses(useInfo: .init(), chain: .external, indexes: 0..<20)
        let sortedAddresses = addresses.keys.sorted().map { addresses[$0]!.description }
        let expectedAddresses = [
            "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c",
            "bc1qp6rfclasvmwys7w7j4svgc2mrujq9m73s5shpw4e799hwkdcqlcsj464fw",
            "bc1qsflxzyj2f2evshspl9n5n745swcvs5k7p5t8qdww5unxpjwdvw5qx53ms4",
            "bc1qmhmj2mswyvyj4az32mzujccvd4dgr8s0lfzaum4n4uazeqc7xxvsr7e28n",
            "bc1qjeu2wa5jwvs90tv9t9xz99njnv3we3ux04fn7glw3vqsk4ewuaaq9kdc9t",
            "bc1qc6626sa08a4ktk3nqjrr65qytt9k273u24mfy2ld004g76jzxmdqjgpm2c",
            "bc1qwlq7jjqcklrcqypvdndjx0fyrudgrymm67gcx3e09sekgs28u47smq0lx5",
            "bc1qx8qq9k2mtqarugg3ctcsm2um22ahmq5uttrecy5ufku0ukfgpwrs7epn38",
            "bc1qgrs4qzvw4aat2k38fvmrqf3ucaanqz2wxe5yy5cewwmqn06evxgq02wv43",
            "bc1qnkpr4y7fp7jwad3gfngczwsv9069rq96cl7lpq4h9j3eng9mwjzsssr520",
            "bc1q7yzadku3kxs855wgjxnyr2nk3e44ed75p07lzhnj53ynpczg78nq0leae5",
            "bc1qpg9ag0ugqeucujyagca0n3httpgrgcsxftfgpymvmdeuyyejq9ks79c99t",
            "bc1qt2sv92tuklq28hptplvq7v75mmc8h6a0ynd7vd7y0h07mr8uzf5seh30gh",
            "bc1qdyfk0c5ksrxg6klz93acchg0xvavduzv3g4zj02fa3tm2yfy445q27zmar",
            "bc1qrpfz6zpargqu9s2qy0ef9uk82x6fcg6jfwjhxdaewgj880nxj2rqt0hwcm",
            "bc1qz6l0ar69xhk209nfdna68fkkg9tqp7pz7eq8mmu6hf5lvpltfx9slc9y6y",
            "bc1qgcttknnx6z65pdyqckexccvnshzv9wp76705704tpxcpw32y8f2suf5fx8",
            "bc1q0pauhlw2y4nyc2hud7dsmtc97k6kc30nz5u05dt6stahrfwy68tsnvl7l6",
            "bc1qhgv6v7jgxxpf0cpzxd9zga52mx3c5xrnkvchk35ypavesumh8yqscvxrjh",
            "bc1qrshvtv8ldqpdtv4z9z8fsah3plkl57drk7d8xgasgwj6puxpcxessp57hv"
        ]
        XCTAssertEqual(sortedAddresses, expectedAddresses)
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a20173777368286d756c746928312c40302c403129290282d99d6fa403582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d99d70a30180021abd16bee5030007d99d70a1018601f400f480f4d99d6fa503582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d99d70a30180021a5a61ff8e030107d99d70a1018600f400f480f4081abd16bee5",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wsh(multi(1,@0,@1))",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7',
                           4:
                           h'60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 3172384485,
                                 3:
                                 0
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    1,
                                    false,
                                    0,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           )
                        }
                     ),
                     40303(   / hdkey /
                        {
                           3:
                           h'02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea',
                           4:
                           h'f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [],
                                 2:
                                 1516371854,
                                 3:
                                 1
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    0,
                                    false,
                                    0,
                                    false,
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           3172384485
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPairKey() throws {
        let source = "wpkh([37b5eed4/84'/0'/0']xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23/<0;1>/*)"
        let desc = try OutputDescriptor(source)

        XCTAssertNil(desc.hdKey(chain: nil, addressIndex: 10))
        XCTAssertNil(desc.hdKey(chain: .external, addressIndex: nil))

        let hdKey1 = desc.hdKey(chain: .external, addressIndex: 10)!.fullDescription
        XCTAssertEqual(hdKey1†, "[37b5eed4/84'/0'/0'/0/10]xpub6B7xKojKUGv71T4NppfMXVG3kpdJpGD4Q9293eCUeUK2seCWokQcfjrhss5jTyh7eL9xBmANUGCu4ouKndSaKSELp6TqCMREMBc59SjBXGo")
        let hdKey2 = desc.hdKey(chain: .internal, addressIndex: 10)!.fullDescription
        XCTAssertEqual(hdKey2†, "[37b5eed4/84'/0'/0'/1/10]xpub6BAS2fSgeDDjJuRizuj5sUeCWgYF5psPVAJxgHbeL2os6drBt9H9BJzWwqkVnn2J33V2vUcpHV5DzJj2UKoZctBLUVy7QBH9Y53XtpE92SE")
        let hdKey3 = desc.hdKey(chain: .internal, addressIndex: 11)!.fullDescription
        XCTAssertEqual(hdKey3†, "[37b5eed4/84'/0'/0'/1/11]xpub6BAS2fSgeDDjMMh78CyFAZgAifM4iuTHLMfjUbv3XYEVN69JfjQ6jgppmkrTfuRxyXzo9YCuPXw7kdEwtBwqRKwGymscqMPTGyqFcNc2uZC")

        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016877706b68284030290281d99d6fa503582103fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a8806d99d70a201861854f500f500f5021a37b5eed407d99d70a101838400f401f480f4081a0d5de1d7",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f',
                           4:
                           h'72ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a88',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [84, true, 0, true, 0, true],
                                 2:
                                 934670036
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    [0, false, 1, false],
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           224256471
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testPairAddress() throws {
        let source = "wpkh([37b5eed4/84'/0'/0']xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23/<0;1>/*)"
        let desc = try OutputDescriptor(source)
        
        XCTAssertNil(desc.address(useInfo: .init(), chain: nil, addressIndex: 10))
        XCTAssertNil(desc.address(useInfo: .init(), chain: .external, addressIndex: nil))
        
        let address1 = desc.address(useInfo: .init(), chain: .external, addressIndex: 10)
        XCTAssertEqual(address1†, "bc1qe6hd9hc3cxy8fc88rpc6zja0w8urkzs902qw56")
        let address2 = desc.address(useInfo: .init(), chain: .internal, addressIndex: 10)
        XCTAssertEqual(address2†, "bc1qcatr2qs60xldaftxltz7kshsnya354mdnvwswc")
        let address3 = desc.address(useInfo: .init(), chain: .internal, addressIndex: 11)
        XCTAssertEqual(address3†, "bc1qx3qm9wz8eykx37s40mqfnd8rdfrsv374qqnl43")
        
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016877706b68284030290281d99d6fa503582103fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a8806d99d70a201861854f500f500f5021a37b5eed407d99d70a101838400f401f480f4081a0d5de1d7",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f',
                           4:
                           h'72ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a88',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [84, true, 0, true, 0, true],
                                 2:
                                 934670036
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    [0, false, 1, false],
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           224256471
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testParsePair() throws {
        let source = "wpkh([37b5eed4/84'/0'/0']xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23/<0;1>/*)"
        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a2016877706b68284030290281d99d6fa503582103fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a8806d99d70a201861854f500f500f5021a37b5eed407d99d70a101838400f401f480f4081a0d5de1d7",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wpkh(@0)",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'03fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f',
                           4:
                           h'72ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a88',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [84, true, 0, true, 0, true],
                                 2:
                                 934670036
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    [0, false, 1, false],
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           224256471
                        }
                     )
                  ]
               }
            )
            """
        ))
    }
    
    func testMultikey() throws {
        let source = "wsh(sortedmulti(2,[dc567276/48'/0'/0'/2']xpub6DiYrfRwNnjeX4vHsWMajJVFKrbEEnu8gAW9vDuQzgTWEsEHE16sGWeXXUV1LBWQE1yCTmeprSNcqZ3W74hqVdgDbtYHUv3eM4W2TEUhpan/<0;1>/*,[f245ae38/48'/0'/0'/2']xpub6DnT4E1fT8VxuAZW29avMjr5i99aYTHBp9d7fiLnpL5t4JEprQqPMbTw7k7rh5tZZ2F5g8PJpssqrZoebzBChaiJrmEvWwUTEMAbHsY39Ge/<0;1>/*,[c5d87297/48'/0'/0'/2']xpub6DjrnfAyuonMaboEb3ZQZzhQ2ZEgaKV2r64BFmqymZqJqviLTe1JzMr2X2RfQF892RH7MyYUbcy77R7pPu1P71xoj8cDUMNhAMGYzKR4noZ/<0;1>/*))"
        var desc = try OutputDescriptor(source)
        desc.name = "Satoshi's Stash"

        XCTAssert(checkRoundTrip(
            source: source,
            cborHex: "d99d74a301781c77736828736f727465646d756c746928322c40302c40312c403229290283d99d6fa5035821021c0b479ecf6e67713ddf0c43b634592f51c037b6f951fb1dc6361a98b1e5735e0458206b3a4cfb6a45f6305efe6e0e976b5d26ba27f7c344d7fc7abef7be2d06d52dfd06d99d70a201881830f500f500f502f5021adc56727607d99d70a101838400f401f480f4081a18f8c2e7d99d6fa50358210397fcf2274abd243d42d42d3c248608c6d1935efca46138afef43af08e9712896045820c887c72d9d8ac29cddd5b2b060e8b0239039a149c784abe6079e24445db4aa8a06d99d70a201881830f500f500f502f5021af245ae3807d99d70a101838400f401f480f4081a221eb5a0d99d6fa5035821028342f5f7773f6fab374e1c2d3ccdba26bc0933fc4f63828b662b4357e4cc37910458205afed56d755c088320ec9bc6acd84d33737b580083759e0a0ff8f26e429e0b7706d99d70a201881830f500f500f502f5021ac5d8729707d99d70a101838400f401f480f4081a1c0ae906036f5361746f7368692773205374617368",
            diag: """
            40308(   / output-descriptor /
               {
                  1:
                  "wsh(sortedmulti(2,@0,@1,@2))",
                  2:
                  [
                     40303(   / hdkey /
                        {
                           3:
                           h'021c0b479ecf6e67713ddf0c43b634592f51c037b6f951fb1dc6361a98b1e5735e',
                           4:
                           h'6b3a4cfb6a45f6305efe6e0e976b5d26ba27f7c344d7fc7abef7be2d06d52dfd',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    48,
                                    true,
                                    0,
                                    true,
                                    0,
                                    true,
                                    2,
                                    true
                                 ],
                                 2:
                                 3696652918
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    [0, false, 1, false],
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           418956007
                        }
                     ),
                     40303(   / hdkey /
                        {
                           3:
                           h'0397fcf2274abd243d42d42d3c248608c6d1935efca46138afef43af08e9712896',
                           4:
                           h'c887c72d9d8ac29cddd5b2b060e8b0239039a149c784abe6079e24445db4aa8a',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    48,
                                    true,
                                    0,
                                    true,
                                    0,
                                    true,
                                    2,
                                    true
                                 ],
                                 2:
                                 4064652856
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    [0, false, 1, false],
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           572437920
                        }
                     ),
                     40303(   / hdkey /
                        {
                           3:
                           h'028342f5f7773f6fab374e1c2d3ccdba26bc0933fc4f63828b662b4357e4cc3791',
                           4:
                           h'5afed56d755c088320ec9bc6acd84d33737b580083759e0a0ff8f26e429e0b77',
                           6:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    48,
                                    true,
                                    0,
                                    true,
                                    0,
                                    true,
                                    2,
                                    true
                                 ],
                                 2:
                                 3319296663
                              }
                           ),
                           7:
                           40304(   / keypath /
                              {
                                 1:
                                 [
                                    [0, false, 1, false],
                                    [],
                                    false
                                 ]
                              }
                           ),
                           8:
                           470477062
                        }
                     )
                  ],
                  3:
                  "Satoshi's Stash"
               }
            )
            """,
            name: "Satoshi's Stash"
        ))
    }
}
