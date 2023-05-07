//
//  HDKeyTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 10/5/21.
//

import XCTest
import BCFoundation
import WolfBase

class HDKeyTests: XCTestCase {
    let bip39Seed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
    
    func testDerivationPath() {
        let path1 = DerivationPath(string: "44'/60'/0'/0/0", requireFixed: true)
        XCTAssertEqual(path1†, "44'/60'/0'/0/0")
        let path2 = DerivationPath(string: "44'/60'/0'/0/*", requireFixed: true)
        XCTAssertNil(path2)
        let path3 = DerivationPath(string: "", requireFixed: true)
        XCTAssertEqual(path3†, "")
    }
    
    func testSeedToHDKey() throws {
        let hdKey = try HDKey(bip39Seed: bip39Seed)
        XCTAssertEqual(hdKey.base58PrivateKey†, "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF")
    }
    
    func testBase58ToHDKey() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        XCTAssertEqual(hdKey.base58†, xpriv)
        
        XCTAssertThrowsError(try HDKey(base58: "invalid"))
    }
    
    func testXpriv() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        XCTAssertEqual(hdKey.base58PrivateKey, xpriv)
    }
    
    func testXpub() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpriv)
        
        XCTAssertEqual(hdKey.base58PublicKey, xpub)
    }
    
    func testTpub() throws {
        let tpriv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let hdKey = try HDKey(base58: tpriv)

        XCTAssertEqual(hdKey.base58PublicKey, tpub)
    }
    
    func testPubKey() throws {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpub)
        XCTAssertEqual(hdKey.ecPublicKey.data, ‡"02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd")
    }
    
    func testParseXpub() throws {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpub)
        XCTAssertEqual(hdKey.base58†, xpub)
        XCTAssertEqual(hdKey.base58PublicKey, xpub)
        XCTAssertNil(hdKey.base58PrivateKey)
    }

    func testParseTpub() throws {
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let hdKey = try HDKey(base58: tpub)
        XCTAssertEqual(hdKey.base58†, tpub)
        XCTAssertEqual(hdKey.base58PublicKey, tpub)
        XCTAssertNil(hdKey.base58PrivateKey)
    }
    
    func testFingerprint() throws {
        let hdKey = try HDKey(bip39Seed: bip39Seed)
        XCTAssertEqual(hdKey.keyFingerprintData, ‡"b4e3f5ed")
    }
    
    func testOriginFingerPrint() throws {
        let hdKey = try HDKey(bip39Seed: bip39Seed)
        XCTAssertNil(hdKey.originFingerprint)

        let childKey = try HDKey(parent: hdKey, childDerivation: BasicDerivationStep(0))
        XCTAssertEqual(childKey.originFingerprint?.hex, "b4e3f5ed")

        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let key = try HDKey(base58: tpub, parent: DerivationPath(origin: .fingerprint(0xb4e3f5ed)))
        XCTAssertEqual(key.originFingerprint?.hex, "b4e3f5ed")
    }
    
    func testInferFingerprintAtDepthZero() throws {
        let masterKeyXpriv = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
        let key = try HDKey(base58: masterKeyXpriv)
        XCTAssertEqual(key.originFingerprint?.hex, "d90c6a4f")
        XCTAssertEqual(key.parent.origin, .fingerprint(0xd90c6a4f))
    }
    
    func testRelativePathFromString() {
        let path = DerivationPath(string: "0'/0")!
        XCTAssert(BCFoundation.isEqual(path.steps, [BasicDerivationStep(0, isHardened: true), BasicDerivationStep(0)]))
        XCTAssertEqual(path†, "0'/0")
        XCTAssertNil(path.origin)
    }
    
    func testAbsolutePathFromString() {
        let path = DerivationPath(string: "m/0h/0")! // 0' and 0h are treated the same
        XCTAssert(BCFoundation.isEqual(path.steps, [BasicDerivationStep(0, isHardened: true), BasicDerivationStep(0)]))
        XCTAssertEqual(path.toString(format: .tickMark), "m/0'/0")
        XCTAssertEqual(path.toString(format: .letter), "m/0h/0")
        XCTAssertEqual(path†, "m/0'/0")
        XCTAssertEqual(path.origin, .master)
    }
    
    func testRelativePathFromInt() {
        var path: DerivationPath
        path = DerivationPath(index: 0)
        XCTAssert(BCFoundation.isEqual(path.steps, [BasicDerivationStep(0)]))
        XCTAssertEqual(path†, "0")
        XCTAssertNil(ChildIndex(UInt32.max))
    }
    
    func testAbsolutePathFromInt() {
        var path: DerivationPath
        path = DerivationPath(index: 0, origin: .master)
        XCTAssertEqual(path†, "m/0")
    }
    
    func testDerive() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        
        let derivation = DerivationPath(index: 0)
        let childKey = try HDKey(parent: hdKey, childDerivationPath: derivation)

        XCTAssertEqual(childKey.base58PrivateKey, "xprv9vEG8CuCbvqnJXhr1ZTHZYJcYqGMZ8dkphAUT2CDZsfqewNpq42oSiFgBXXYwDWAHXVbHew4uBfiHNAahRGJ8kUWwqwTGSXUb4wrbWz9eqo")
    }
    
    func testDeriveHardened() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        
        let derivation = DerivationPath(step: BasicDerivationStep(0, isHardened: true))
        let childKey = try HDKey(parent: hdKey, childDerivationPath: derivation)

        XCTAssertEqual(childKey.base58PrivateKey, "xprv9vEG8CuLwbNkVNhb56dXckENNiU1SZEgwEAokv1yLodVwsHMRbAFyUMoMd5uyKEgPDgEPBwNfa42v5HYvCvT1ymQo1LQv9h5LtkBMvQD55b")
    }
    
    func testDerivePath() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)

        let path = DerivationPath(string: "m/0'/0")!
        let childKey = try HDKey(parent: hdKey, childDerivationPath: path)

        XCTAssertEqual(childKey.base58PrivateKey, "xprv9xcgxEx7PAbqP2YSijYjX38Vo6dV4i7g9ApmPRAkofDzQ6Hf4c3nBNRfW4EKSm2uhk4FBbjNFGjhZrATqLVKM2JjhsxSrUsDdJYK4UKhyQt")
    }
    
    func testDeriveFromXpub() throws {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpub)
        
        let path = DerivationPath(string: "m/0")!
        let childKey = try HDKey(parent: hdKey, childDerivationPath: path)

        XCTAssertEqual(childKey.base58PublicKey, "xpub69DcXiS6SJQ5X1nK7azHvgFM6s6qxbMcBv65FQbq8DCpXjhyNbM3zWaA2p4L7Na2siUqFvyuK9W11J6GjqQhtPeJkeadtSpFcf6XLdKsZLZ")
        XCTAssertNil(childKey.base58PrivateKey)
        
        let hardenedPath = DerivationPath(string: "m/0'")!
        XCTAssertThrowsError(try HDKey(parent: hdKey, childDerivationPath: hardenedPath))
    }

    func testDeriveWithAbsolutePath() throws {
        // Derivation is at depth 4
        let xpub = "xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi"
        let hdKey = try HDKey(base58: xpub)
        
        let relativePath = DerivationPath(string: "0/0")!
        let expectedChildKey = try HDKey(parent: hdKey, derivedKeyType: .public, childDerivationPath: relativePath)
        
        // This should ignore the first 4 levels
        let absolutePath = DerivationPath(string: "m/48h/0h/0h/2h/0/0")!
        let childKey = try HDKey(parent: hdKey, derivedKeyType: .public, childDerivationPath: absolutePath)
        
        XCTAssertEqual(childKey.base58PublicKey, expectedChildKey.base58PublicKey)
    }
}
