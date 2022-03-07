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
    func testRaw() throws {
        let source = "raw(76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac)"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc.source, source)
        XCTAssertEqual(desc.unparsed, source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90198581976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        XCTAssertEqual(desc.ur†, "ur:crypto-output/taadmkhdcfkoptbbrnykoeytonimmwpkpadkhkyldrtatklkwnnskgrnlopslbzcfrio")
    }
    
    func testPK() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = try HDKey(base58: tprv)
        let ecPub = hdKey.ecPublicKey.hex
        let ecPubUncompressed = hdKey.ecPublicKey.uncompressed.hex
        let wif = hdKey.ecPrivateKey!.wif
        let tpub = hdKey.base58PublicKey!
        
        let desc1 = try OutputDescriptor("pk(\(ecPub))")
        XCTAssertEqual(desc1.scriptPubKey()†, "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]")
        XCTAssertEqual(desc1.unparsed, desc1.source)
        XCTAssertEqual(desc1.taggedCBOR.hex, "d90134d90192d90132a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2")
        
        let desc2 = try OutputDescriptor("pk(\(ecPubUncompressed))")
        XCTAssertEqual(desc2.scriptPubKey()†, "pk:[04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG]")
        XCTAssertEqual(desc2.unparsed, desc2.source)
        XCTAssertEqual(desc2.taggedCBOR.hex, "d90134d90192d90132a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27")

        let desc3 = try OutputDescriptor("pk(\(wif))")
        XCTAssertEqual(desc3.scriptPubKey()†, "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]")
        XCTAssertEqual(desc3.unparsed, desc3.source)
        XCTAssertEqual(desc3.taggedCBOR.hex, "d90134d90192d90132a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e")

        let desc4 = try OutputDescriptor("pk(\(tprv))")
        XCTAssertEqual(desc4.scriptPubKey()†, "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]")
        XCTAssertEqual(desc4.unparsed, desc4.source)
        XCTAssertEqual(desc4.taggedCBOR.hex, "d90134d90192d9012fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")

        let desc5 = try OutputDescriptor("pk(\(tpub))")
        XCTAssertEqual(desc5.scriptPubKey()†, "pk:[03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG]")
        XCTAssertEqual(desc5.unparsed, desc5.source)
        XCTAssertEqual(desc5.taggedCBOR.hex, "d90134d90192d9012fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")
    }
    
    func testCosigner() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = try HDKey(base58: tprv)
        let ecPub = hdKey.ecPublicKey.hex
        let ecPubUncompressed = hdKey.ecPublicKey.uncompressed.hex
        let wif = hdKey.ecPrivateKey!.wif
        let tpub = hdKey.base58PublicKey!
        
        let desc1 = try OutputDescriptor("cosigner(\(ecPub))")
        XCTAssertNil(desc1.scriptPubKey())
        XCTAssertEqual(desc1.unparsed, desc1.source)
        XCTAssertEqual(desc1.taggedCBOR.hex, "d90134d9019ad90132a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2")
        
        let desc2 = try OutputDescriptor("cosigner(\(ecPubUncompressed))")
        XCTAssertNil(desc2.scriptPubKey())
        XCTAssertEqual(desc2.unparsed, desc2.source)
        XCTAssertEqual(desc2.taggedCBOR.hex, "d90134d9019ad90132a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27")

        let desc3 = try OutputDescriptor("cosigner(\(wif))")
        XCTAssertNil(desc3.scriptPubKey())
        XCTAssertEqual(desc3.unparsed, desc3.source)
        XCTAssertEqual(desc3.taggedCBOR.hex, "d90134d9019ad90132a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e")

        let desc4 = try OutputDescriptor("cosigner(\(tprv))")
        XCTAssertNil(desc4.scriptPubKey())
        XCTAssertEqual(desc4.unparsed, desc4.source)
        XCTAssertEqual(desc4.taggedCBOR.hex, "d90134d9019ad9012fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")

        let desc5 = try OutputDescriptor("cosigner(\(tpub))")
        XCTAssertNil(desc5.scriptPubKey())
        XCTAssertEqual(desc5.unparsed, desc5.source)
        XCTAssertEqual(desc5.taggedCBOR.hex, "d90134d9019ad9012fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")
    }

    func testPKH() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = try HDKey(base58: tprv)
        let ecPub = hdKey.ecPublicKey.hex
        let ecPubUncompressed = hdKey.ecPublicKey.uncompressed.hex
        let wif = hdKey.ecPrivateKey!.wif
        let tpub = hdKey.base58PublicKey!
        
        let desc1 = try OutputDescriptor("pkh(\(ecPub))")
        XCTAssertEqual(desc1.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc1.unparsed, desc1.source)
        XCTAssertEqual(desc1.taggedCBOR.hex, "d90134d90193d90132a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2")

        let desc2 = try OutputDescriptor("pkh(\(ecPubUncompressed))")
        XCTAssertEqual(desc2.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc2.unparsed, desc2.source)
        XCTAssertEqual(desc2.taggedCBOR.hex, "d90134d90193d90132a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27")

        let desc3 = try OutputDescriptor("pkh(\(wif))")
        XCTAssertEqual(desc3.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc3.unparsed, desc3.source)
        XCTAssertEqual(desc3.taggedCBOR.hex, "d90134d90193d90132a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e")

        let desc4 = try OutputDescriptor("pkh(\(tprv))")
        XCTAssertEqual(desc4.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc4.unparsed, desc4.source)
        XCTAssertEqual(desc4.taggedCBOR.hex, "d90134d90193d9012fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")

        let desc5 = try OutputDescriptor("pkh(\(tpub))")
        XCTAssertEqual(desc5.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc5.unparsed, desc5.source)
        XCTAssertEqual(desc5.taggedCBOR.hex, "d90134d90193d9012fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")
    }
    
    func testWPKH() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = try HDKey(base58: tprv)
        let ecPub = hdKey.ecPublicKey.hex
        let ecPubUncompressed = hdKey.ecPublicKey.uncompressed.hex
        let wif = hdKey.ecPrivateKey!.wif
        let tpub = hdKey.base58PublicKey!
        
        let desc1 = try OutputDescriptor("wpkh(\(ecPub))")
        XCTAssertEqual(desc1.scriptPubKey()†, "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]")
        XCTAssertEqual(desc1.unparsed, desc1.source)
        XCTAssertEqual(desc1.taggedCBOR.hex, "d90134d90194d90132a103582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2")

        let desc2 = try OutputDescriptor("wpkh(\(ecPubUncompressed))")
        XCTAssertEqual(desc2.scriptPubKey()†, "wpkh:[OP_0 335f3a94aeed3518f0baedc04330945e3dd0744b]")
        XCTAssertEqual(desc2.unparsed, desc2.source)
        XCTAssertEqual(desc2.taggedCBOR.hex, "d90134d90194d90132a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27")

        let desc3 = try OutputDescriptor("wpkh(\(wif))")
        XCTAssertEqual(desc3.scriptPubKey()†, "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]")
        XCTAssertEqual(desc3.unparsed, desc3.source)
        XCTAssertEqual(desc3.taggedCBOR.hex, "d90134d90194d90132a202f5035820347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e")

        let desc4 = try OutputDescriptor("wpkh(\(tprv))")
        XCTAssertEqual(desc4.scriptPubKey()†, "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]")
        XCTAssertEqual(desc4.unparsed, desc4.source)
        XCTAssertEqual(desc4.taggedCBOR.hex, "d90134d90194d9012fa602f503582100347c4acb73f7bf2268b958230e215986eda87a984959c4ddbd4d62c07de6310e0458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")

        let desc5 = try OutputDescriptor("wpkh(\(tpub))")
        XCTAssertEqual(desc5.scriptPubKey()†, "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]")
        XCTAssertEqual(desc5.unparsed, desc5.source)
        XCTAssertEqual(desc5.taggedCBOR.hex, "d90134d90194d9012fa503582103e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f20458205b74b3709e229bc49589525249b8997e83a5387c27fef500f2f2e1d608757bb305d90131a1020106d90130a3018200f5021a4efd3ded0303081ae0c98d67")
    }
    
    func testMulti() throws {
        let m1 = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
        let desc1 = try OutputDescriptor(m1);
        XCTAssertEqual(desc1.scriptPubKey()†, "multi:[OP_1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc OP_2 OP_CHECKMULTISIG]")
        XCTAssertEqual(desc1.unparsed, desc1.source)
        XCTAssertEqual(desc1.taggedCBOR.hex, "d90134d90196a201010282d90132a1035821022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d90132a1035821025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")

        let m2 = "multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)"
        let desc2 = try OutputDescriptor(m2)
        XCTAssertEqual(desc2.scriptPubKey()†, "multi:[OP_2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a OP_3 OP_CHECKMULTISIG]")
        XCTAssertEqual(desc2.unparsed, desc2.source)
        XCTAssertEqual(desc2.taggedCBOR.hex, "d90134d90196a201020283d90132a103582103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7d90132a103582103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbd90132a103582103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a")
    }
    
    func testSortedMulti1() throws {
        func test(_ threshold: Int, _ keys: [String], _ expectedScript: String, _ expectedAddress: String, _ expectedCBOR: String) throws {
            let k = keys.joined(separator: ",")
            let source = "sortedmulti(\(threshold),\(k))"
            let desc = try OutputDescriptor(source)
            XCTAssertEqual(desc.scriptPubKey()?.hex, expectedScript)
            let address = Bitcoin.Address(scriptPubKey: desc.scriptPubKey()!, network: .mainnet)!.string
            XCTAssertEqual(address, expectedAddress)
            XCTAssertEqual(desc.unparsed, source)
            XCTAssertEqual(desc.taggedCBOR.hex, expectedCBOR)
        }

        // https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki#test-vectors

        try test(
            2,
            [
                "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"
            ],
            "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
            "bc1qknwt9mhqpd7hrjrvpqz57zjqk28xlp2h90te6v22en0m3uctnams3pq5ce",
            "d90134d90197a201020282d90132a103582102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8d90132a103582102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"
        )

        try test(
            2,
            [
                "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404"
            ],
            "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed021027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e772102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
            "bc1qud6dmdcc27eg8s5hsy6a075gs49w65l6xtc4cplp6m2d4ggh43wqew2vqs",
            "d90134d90197a201020283d90132a103582102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0d90132a1035821027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77d90132a103582102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404"
        )

        try test(
            2,
            [
                "030000000000000000000000000000000000004141414141414141414141414141",
                "020000000000000000000000000000000000004141414141414141414141414141",
                "020000000000000000000000000000000000004141414141414141414141414140",
                "030000000000000000000000000000000000004141414141414141414141414140"
            ],
            "522102000000000000000000000000000000000000414141414141414141414141414021020000000000000000000000000000000000004141414141414141414141414141210300000000000000000000000000000000000041414141414141414141414141402103000000000000000000000000000000000000414141414141414141414141414154ae",
            "bc1q43l9uw4l5q3d3eltdvf785atcpfys8wad6z4rv6mltnzrzasq0jqp0lwze",
            "d90134d90197a201020284d90132a1035821030000000000000000000000000000000000004141414141414141414141414141d90132a1035821020000000000000000000000000000000000004141414141414141414141414141d90132a1035821020000000000000000000000000000000000004141414141414141414141414140d90132a1035821030000000000000000000000000000000000004141414141414141414141414140"
        )

        try test(
            2,
            [
                "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"
            ],
            "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc1821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
            "bc1q0uyls9kc4acv9ntqw6u096t53jlld4frp4rscrf8fruddhu62p6sy9507s",
            "d90134d90197a201020283d90132a1035821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014dad90132a103582103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9d90132a1035821021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"
        )
    }
    
    func testSortedMulti2() throws {
        let source = "sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH)"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.scriptPubKey()?.asm, "OP_1 02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea 03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7 OP_2 OP_CHECKMULTISIG")
        XCTAssertEqual(desc.unparsed, source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90197a201010282d9012fa301f503582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689d9012fa303582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c081abd16bee5")
    }

    func testAddr() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        let hdKey = try HDKey(base58: tprv)
        let addressp2pkh = Bitcoin.Address(hdKey: hdKey, type: .payToPubKeyHash).string
        XCTAssertEqual(addressp2pkh, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
        
        let desc1 = try OutputDescriptor("addr(\(addressp2pkh))")
        XCTAssertEqual(desc1.scriptPubKey()†, "pkh:[OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc1.unparsed, desc1.source)
        let p2shp2wpkh = Bitcoin.Address(hdKey: hdKey, type: .payToScriptHashPayToWitnessPubKeyHash).string
        XCTAssertEqual(p2shp2wpkh, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
        XCTAssertEqual(desc1.taggedCBOR.hex, "d90134d90133a301d90131a10201020003544efd3ded47d967e4122982422c9d84db60503972")

        let desc2 = try OutputDescriptor("addr(\(p2shp2wpkh))")
        XCTAssertEqual(desc2.scriptPubKey()†, "sh:[OP_HASH160 8fb371a0195598d96e634b9eddb645fa1f128e11 OP_EQUAL]")
        XCTAssertEqual(desc2.unparsed, desc2.source)
        let p2wpkh = Bitcoin.Address(hdKey: hdKey, type: .payToWitnessPubKeyHash).string
        XCTAssertEqual(p2wpkh, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
        XCTAssertEqual(desc2.taggedCBOR.hex, "d90134d90133a301d90131a10201020103548fb371a0195598d96e634b9eddb645fa1f128e11")

        let desc3 = try OutputDescriptor("addr(\(p2wpkh))")
        XCTAssertEqual(desc3.unparsed, desc3.source)
        XCTAssertEqual(desc3.scriptPubKey()†, "wpkh:[OP_0 4efd3ded47d967e4122982422c9d84db60503972]")
        XCTAssertEqual(desc3.taggedCBOR.hex, "d90134d90133a301d90131a10201020203544efd3ded47d967e4122982422c9d84db60503972")
    }
    
    func testHDKey1() throws {
        let source = "pkh([d34db33f/44'/0'/0']xpub6CY2xt3mvQejPFUw26CychtL4GMq1yp41aMW2U27mvThqefpZYwXpGscV26JuVj13Fpg4kgSENheUSbTqm5f8z25zrhXpPVss5zWeMGnAKR/1/*)"
        let desc = try OutputDescriptor(source)
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertTrue(desc.requiresWildcardChildNum)
        XCTAssertNil(desc.scriptPubKey()) // requires wildcard
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 0)†, "pkh:[OP_DUP OP_HASH160 2a05c214617c9b0434c92d0583200a85ef61818f OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 1)†, "pkh:[OP_DUP OP_HASH160 49b2f81eea1ecb5bc97d78f2d8f89d9c861c3cf2 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90193d9012fa503582102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0045820637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2906d90130a20186182cf500f500f5021ad34db33f07d90130a1018401f480f4081a78412e3a")
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
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertTrue(desc.requiresWildcardChildNum)
        XCTAssertNil(desc.scriptPubKey(wildcardChildNum: 0)) // requires private key.
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90193d9012fa603582102b705663fa1839bc7de73fcb18038a75facb7509df15230379147011ebb343140045820d10491ab8729ef3ca5e7555f54f04605d06b01b35e379b2cdc2fcae271410a9805d90131a1020106d90130a20186182cf500f500f5021a4efd3ded07d90130a1018401f580f4081a10d66527")
        
        let lookup: [UInt32 : HDKey] = [
            masterKey.keyFingerprint : masterKey
        ]
        
        let fullPath = purposePath + accountPath
        XCTAssertEqual(fullPath†, "44'/0'/0'")
        
        func privateKeyProvider(key: HDKeyProtocol) -> HDKey? {
            guard
                case let .fingerprint(originFingerprint) = key.parent.origin,
                let masterKey = lookup[originFingerprint],
                let privateKey = try? HDKey(parent: masterKey, childDerivationPath: fullPath)
            else {
                return nil
            }
            return privateKey
        }
        
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 0, privateKeyProvider: privateKeyProvider)†, "pkh:[OP_DUP OP_HASH160 c3d4f598ec80d57820226529645b7805d078cab0 OP_EQUALVERIFY OP_CHECKSIG]")
    }
    
    func test_SH_WPKH() throws {
        let a = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
        let desc = try OutputDescriptor(a)
        XCTAssertEqual(desc.scriptPubKey()†, "sh:[OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90190d90194d90132a103582103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")
    }
    
    func test_WSH_PKH() throws {
        let a = "wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13))"
        let desc = try OutputDescriptor(a)
        XCTAssertEqual(desc.scriptPubKey()†, "wsh:[OP_0 fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90191d90193d90132a103582102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13")
    }
    
    func test_SH_WSH_PKH() throws {
        let a = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"
        let desc = try OutputDescriptor(a)
        XCTAssertEqual(desc.scriptPubKey()†, "sh:[OP_HASH160 55e8d5e8ee4f3604aba23c71c2684fa0a56a3a12 OP_EQUAL]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90190d90191d90193d90132a103582102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13")
    }
    
    func test_SH_MULTI() throws {
        let a = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))"
        let desc = try OutputDescriptor(a)
        XCTAssertEqual(desc.scriptPubKey()†, "sh:[OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90190d90196a201020282d90132a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01d90132a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe")
    }
    
    func test_SH_SORTEDMULTI() throws {
        let a = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
        let desc = try OutputDescriptor(a)
        XCTAssertEqual(desc.scriptPubKey()†, "sh:[OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90190d90197a201020282d90132a103582103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbed90132a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01")
    }
    
    func test_WSH_MULTI() throws {
        let a = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))"
        let desc = try OutputDescriptor(a)
        XCTAssertEqual(desc.scriptPubKey()†, "wsh:[OP_0 773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90191d90196a201020283d90132a103582103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7d90132a103582103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbd90132a103582103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a")
    }
    
    func test_SH_WSH_MULTI() throws {
        let a = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))"
        let desc = try OutputDescriptor(a)
        XCTAssertFalse(desc.requiresWildcardChildNum)
        XCTAssertEqual(desc.scriptPubKey()†, "sh:[OP_HASH160 aec509e284f909f769bb7dda299a717c87cc97ac OP_EQUAL]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90190d90191d90196a201010283d90132a103582103f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8d90132a103582103499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4d90132a103582102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e")
    }
    
    func test_WSH_MULTI_HD() throws {
        let a = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
        let desc = try OutputDescriptor(a)
        XCTAssertTrue(desc.requiresWildcardChildNum)
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 0)†, "wsh:[OP_0 64969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90191d90196a201010282d9012fa401f503582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968907d90130a1018601f400f480f4d9012fa403582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c07d90130a1018600f400f480f4081abd16bee5")
    }
    
    func test_WSH_MULTI_HD_2() throws {
        // This test vector from: https://bitcoindevkit.org/descriptors/
        let a = "wsh(multi(2,tprv8ZgxMBicQKsPePmENhT9N9yiSfTtDoC1f39P7nNmgEyCB6Nm4Qiv1muq4CykB9jtnQg2VitBrWh8PJU8LHzoGMHTrS2VKBSgAz7Ssjf9S3P/0/*,tpubDBYDcH8P2PedrEN3HxWYJJJMZEdgnrqMsjeKpPNzwe7jmGwk5M3HRdSf5vudAXwrJPfUsfvUPFooKWmz79Lh111U51RNotagXiGNeJe3i6t/1/*))"
        let desc = try OutputDescriptor(a)
        let scriptPubKey0 = desc.scriptPubKey(wildcardChildNum: 0)!
        let scriptPubKey1 = desc.scriptPubKey(wildcardChildNum: 1)!
        XCTAssertEqual(Bitcoin.Address(scriptPubKey: scriptPubKey0, network: .testnet)!.string, "tb1qqsat6c82fvdy73rfzye8f7nwxcz3xny7t56azl73g95mt3tmzvgs9a8vjs")
        XCTAssertEqual(Bitcoin.Address(scriptPubKey: scriptPubKey1, network: .testnet)!.string, "tb1q7sgx6gscgtau57jduend6a8l445ahpk3dt3u5zu58rx5qm27lhkqgfdjdr")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90191d90196a201020282d9012fa601f502f5035821004e7fa77f7ca0d1e1417030ebdcf7f89067d7e37ce79a0af77b1c9539011dbf3e04582098b1992f76329c460890752a6087c3e4affeb89c2e78691726c69694893e50dc05d90131a1020107d90130a1018400f480f4d9012fa50358210375556045e9ec973aa370718f1425345a4b326a0a162696000f771c3658e112fd04582036d1c7d5522f8ee297323c43e25ea046ccefc93a2416227adc4d2221872875d205d90131a1020107d90130a1018401f480f4081abde5aaf9")
        XCTAssertEqual(desc.ur†, "ur:crypto-output/taadmetaadmtoeadaoaolftaaddloladykaoykaxhdclaegllboslbkenbttvyfpjodywmuoylyamhiotsvlkevdnybkylkgcemdesadcarsfmaahdcxmkpanldlkoeynsfgaymhkpdrhnltsrvepezeronsdmksinchdsswmtmwldfmgduoahtaadehoyaoadattaaddyoyadlraewklawktaaddlonaxhdclaxkpgohnfewlwpmsftotjojsmybbdaeehtgreyimbkcmdsmtaebsktceenhdvybgzcaahdcxenttsttlgmdlmnvomseyfnfxvohynbfgsfwssoftdkcmcpknuogtcpclltdekptdahtaadehoyaoadattaaddyoyadlradwklawkaycyryvwpkytclpejnro")
    }
    
    func testCombo1() throws {
        // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
        let comboCompressed = "combo(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)"
        let desc = try OutputDescriptor(comboCompressed)
        XCTAssertTrue(desc.isCombo)
        XCTAssertFalse(desc.requiresWildcardChildNum)
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pk)†, "pk:[022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pkh)†, "pkh:[OP_DUP OP_HASH160 9652d86bedf43ad264362e6e6eba6eb764508127 OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .wpkh)†, "wpkh:[OP_0 9652d86bedf43ad264362e6e6eba6eb764508127]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .sh_wpkh)†, "sh:[OP_HASH160 edcbce4e0cce791e8ddb72705133fa3566145fa6 OP_EQUAL]")
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90195d90132a1035821022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01")
    }
    
    func testCombo2() throws {
        // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
        let comboUncompressed = "combo(04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27)"
        let desc = try OutputDescriptor(comboUncompressed)
        XCTAssertTrue(desc.isCombo)
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pk)†, "pk:[04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG]")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pkh)†, "pkh:[OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG]")
        XCTAssertNil(desc.scriptPubKey(comboOutput: .wpkh))
        XCTAssertNil(desc.scriptPubKey(comboOutput: .sh_wpkh))
        XCTAssertEqual(desc.unparsed, desc.source)
        XCTAssertEqual(desc.taggedCBOR.hex, "d90134d90195d90132a103584104e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27")
    }
    
    func testChecksum() throws {
        let source = "pkh([00000000/0'/0']tprv8et1s5VnWCG3v3R6vXX5hprTpdCdcBp3jRuoDByaF9uAkCt5XjfuX52hgh63aWzCYpXNU2YyxAj78qg8PS2EuGUKE8Untk6NVe7FAG8RdLk/*')"
        let expectedChecksum = "3428vapa"
        let checksum = OutputDescriptor.checksum(source)!
        XCTAssertEqual(checksum, expectedChecksum)
    }
}
