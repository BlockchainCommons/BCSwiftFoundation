import XCTest
import BCFoundation
import WolfBase

class EnvelopeRequestTests: XCTestCase {
    func testUseInfo() throws {
        let useInfo = UseInfo(asset: .btc, network: .mainnet)
        let envelope = useInfo.envelope
        XCTAssertEqual(useInfo.envelope.format(context: globalFormatContext), """
        btc [
            isA: asset
            network: mainNet [
                isA: network
            ]
        ]
        """)
        XCTAssertEqual(useInfo, try UseInfo(envelope))
    }
    
    func testHDKey() throws {
        let bip39Seed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
        let masterKey = try HDKey(bip39Seed: bip39Seed)
        
        let masterEnvelope = masterKey.envelope
        XCTAssertEqual(masterEnvelope.format(context: globalFormatContext), """
        Bytes(33) [
            isA: bip32key
            isA: masterKey
            isA: privateKey
            asset: btc [
                isA: asset
                network: mainNet [
                    isA: network
                ]
            ]
            chainCode: Bytes(32)
        ]
        """)
        let masterKey2 = try HDKey(masterEnvelope)
        XCTAssertEqual(masterKey, masterKey2)

        let absolutePath = DerivationPath(string: "m/48h/0h/0h/2h/0/0")!
        var childKey = try HDKey(parent: masterKey, derivedKeyType: .public, childDerivationPath: absolutePath)
        childKey.name = "This is the key name."
        childKey.note = "This is the key note."
        
        let childEnvelope = childKey.envelope
        XCTAssertEqual(childEnvelope.format(context: globalFormatContext), """
        Bytes(33) [
            isA: bip32key
            isA: publicKey
            asset: btc [
                isA: asset
                network: mainNet [
                    isA: network
                ]
            ]
            chainCode: Bytes(32)
            hasName: "This is the key name."
            note: "This is the key note."
            parent: crypto-keypath(Map) [
                isA: derivationPath
            ]
            parentFingerprint: 3912704230
        ]
        """)
        let childKey2 = try HDKey(childEnvelope)
        XCTAssertEqual(childKey, childKey2)
    }
}
