//
//  HDKeyTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 10/5/21.
//

import Testing
import BCFoundation
import WolfBase

struct HDKeyTests {
    let bip39Seed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
    
    @Test func testDerivationPath() {
        let path1 = DerivationPath(string: "44'/60'/0'/0/0", requireFixed: true)
        #expect(path1† == "44'/60'/0'/0/0")
        let path2 = DerivationPath(string: "44'/60'/0'/0/*", requireFixed: true)
        #expect(path2 == nil)
        let path3 = DerivationPath(string: "", requireFixed: true)
        #expect(path3† == "")
    }
    
    @Test func testSeedToHDKey() throws {
        let hdKey = try HDKey(bip39Seed: bip39Seed)
        #expect(hdKey.base58PrivateKey† == "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF")
    }
    
    @Test func testBase58ToHDKey() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        #expect(hdKey.base58† == xpriv)
        
        #expect(throws: (any Error).self) { try HDKey(base58: "invalid") }
    }
    
    @Test func testXpriv() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        #expect(hdKey.base58PrivateKey == xpriv)
    }
    
    @Test func testXpub() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpriv)
        
        #expect(hdKey.base58PublicKey == xpub)
    }
    
    @Test func testTpub() throws {
        let tpriv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let hdKey = try HDKey(base58: tpriv)

        #expect(hdKey.base58PublicKey == tpub)
    }
    
    @Test func testPubKey() throws {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpub)
        #expect(hdKey.ecdsaPublicKey.data == ‡"02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd")
    }
    
    @Test func testParseXpub() throws {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpub)
        #expect(hdKey.base58† == xpub)
        #expect(hdKey.base58PublicKey == xpub)
        #expect(hdKey.base58PrivateKey == nil)
    }

    @Test func testParseTpub() throws {
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let hdKey = try HDKey(base58: tpub)
        #expect(hdKey.base58† == tpub)
        #expect(hdKey.base58PublicKey == tpub)
        #expect(hdKey.base58PrivateKey == nil)
    }
    
    @Test func testFingerprint() throws {
        let hdKey = try HDKey(bip39Seed: bip39Seed)
        #expect(hdKey.keyFingerprintData == ‡"b4e3f5ed")
    }
    
    @Test func testOriginFingerPrint() throws {
        let hdKey = try HDKey(bip39Seed: bip39Seed)
        #expect(hdKey.originFingerprint == nil)

        let childKey = try HDKey(parent: hdKey, childDerivation: BasicDerivationStep(0))
        #expect(childKey.originFingerprint?.hex == "b4e3f5ed")

        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let key = try HDKey(base58: tpub, parent: DerivationPath(origin: .fingerprint(0xb4e3f5ed)))
        #expect(key.originFingerprint?.hex == "b4e3f5ed")
    }
    
    @Test func testInferFingerprintAtDepthZero() throws {
        let masterKeyXpriv = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
        let key = try HDKey(base58: masterKeyXpriv)
        #expect(key.originFingerprint?.hex == "d90c6a4f")
        #expect(key.parent.origin == .fingerprint(0xd90c6a4f))
    }
    
    @Test func testRelativePathFromString() {
        let path = DerivationPath(string: "0'/0")!
        #expect(BCFoundation.isEqual(path.steps, [BasicDerivationStep(0, isHardened: true), BasicDerivationStep(0)]) == true)
        #expect(path† == "0'/0")
        #expect(path.origin == nil)
    }
    
    @Test func testAbsolutePathFromString() {
        let path = DerivationPath(string: "m/0h/0")! // 0' and 0h are treated the same
        #expect(BCFoundation.isEqual(path.steps, [BasicDerivationStep(0, isHardened: true), BasicDerivationStep(0)]) == true)
        #expect(path.toString(format: .tickMark) == "m/0'/0")
        #expect(path.toString(format: .letter) == "m/0h/0")
        #expect(path† == "m/0'/0")
        #expect(path.origin == .master)
    }
    
    @Test func testRelativePathFromInt() {
        var path: DerivationPath
        path = DerivationPath(index: 0)
        #expect(BCFoundation.isEqual(path.steps, [BasicDerivationStep(0)]) == true)
        #expect(path† == "0")
        #expect(ChildIndex(UInt32.max) == nil)
    }
    
    @Test func testAbsolutePathFromInt() {
        var path: DerivationPath
        path = DerivationPath(index: 0, origin: .master)
        #expect(path† == "m/0")
    }
    
    @Test func testDerive() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        
        let derivation = DerivationPath(index: 0)
        let childKey = try HDKey(parent: hdKey, childDerivationPath: derivation)

        #expect(childKey.base58PrivateKey == "xprv9vEG8CuCbvqnJXhr1ZTHZYJcYqGMZ8dkphAUT2CDZsfqewNpq42oSiFgBXXYwDWAHXVbHew4uBfiHNAahRGJ8kUWwqwTGSXUb4wrbWz9eqo")
    }
    
    @Test func testDeriveHardened() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)
        
        let derivation = DerivationPath(step: BasicDerivationStep(0, isHardened: true))
        let childKey = try HDKey(parent: hdKey, childDerivationPath: derivation)

        #expect(childKey.base58PrivateKey == "xprv9vEG8CuLwbNkVNhb56dXckENNiU1SZEgwEAokv1yLodVwsHMRbAFyUMoMd5uyKEgPDgEPBwNfa42v5HYvCvT1ymQo1LQv9h5LtkBMvQD55b")
    }
    
    @Test func testDerivePath() throws {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = try HDKey(base58: xpriv)

        let path = DerivationPath(string: "m/0'/0")!
        let childKey = try HDKey(parent: hdKey, childDerivationPath: path)

        #expect(childKey.base58PrivateKey == "xprv9xcgxEx7PAbqP2YSijYjX38Vo6dV4i7g9ApmPRAkofDzQ6Hf4c3nBNRfW4EKSm2uhk4FBbjNFGjhZrATqLVKM2JjhsxSrUsDdJYK4UKhyQt")
    }
    
    @Test func testDeriveFromXpub() throws {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = try HDKey(base58: xpub)
        
        let path = DerivationPath(string: "m/0")!
        let childKey = try HDKey(parent: hdKey, childDerivationPath: path)

        #expect(childKey.base58PublicKey == "xpub69DcXiS6SJQ5X1nK7azHvgFM6s6qxbMcBv65FQbq8DCpXjhyNbM3zWaA2p4L7Na2siUqFvyuK9W11J6GjqQhtPeJkeadtSpFcf6XLdKsZLZ")
        #expect(childKey.base58PrivateKey == nil)
        
        let hardenedPath = DerivationPath(string: "m/0'")!
        #expect(throws: (any Error).self) { try HDKey(parent: hdKey, childDerivationPath: hardenedPath) }
    }

    @Test func testDeriveWithAbsolutePath() throws {
        // Derivation is at depth 4
        let xpub = "xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi"
        let hdKey = try HDKey(base58: xpub)
        
        let relativePath = DerivationPath(string: "0/0")!
        let expectedChildKey = try HDKey(parent: hdKey, derivedKeyType: .public, childDerivationPath: relativePath)
        
        // This should ignore the first 4 levels
        let absolutePath = DerivationPath(string: "m/48h/0h/0h/2h/0/0")!
        let childKey = try HDKey(parent: hdKey, derivedKeyType: .public, childDerivationPath: absolutePath)
        
        #expect(childKey.base58PublicKey == expectedChildKey.base58PublicKey)
    }
    
    @Test func testIdentityDigestSource() throws {
        let keyData = ‡"026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6"
        let chainCode = ‡"ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85"
        let useInfo = UseInfo(asset: .btc, network: .testnet)
        var keySource: [CBOR] = []
        keySource.append(keyData.cbor)
        keySource.append(chainCode.cbor)
        keySource.append(useInfo.asset.rawValue.cbor)
        keySource.append(useInfo.network.rawValue.cbor)
        #expect(keySource.cbor.diagnostic(tags: globalTags) ==
        """
        [
           h'026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6',
           h'ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85',
           0,
           1
        ]
        """)
        #expect(keySource.cbor.hex(annotate: true) ==
        """
        84                                       # array(4)
           5821                                  # bytes(33)
              026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6
           5820                                  # bytes(32)
              ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85
           00                                    # unsigned(0)
           01                                    # unsigned(1)
        """)
        
        let digestSource = keySource.cborData
        let expectedDigestSource = ‡"845821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a65820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c850001"
        #expect(digestSource == expectedDigestSource)

        let digest = expectedDigestSource.sha256Digest
        let expectedDigest = ‡"362af3038da7600ad1581c19161c8594aafafc24e5acf1aefc8f7a0bbe366df2"
        #expect(digest == expectedDigest)
        
        let hdKey = HDKey(isMaster: true, keyType: .private, keyData: keyData, chainCode: chainCode, useInfo: useInfo, parent: nil, children: nil, parentFingerprint: nil, name: "", note: "")
        #expect(hdKey.identityDigestSource == expectedDigestSource)
        #expect(hdKey.identityDigest == digest)
    }
}
