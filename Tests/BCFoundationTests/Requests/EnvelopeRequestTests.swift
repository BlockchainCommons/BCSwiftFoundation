import Testing
import BCFoundation
import WolfBase

struct EnvelopeRequestTests {
    init() async {
        await addKnownFunctionExtensions()
        await addKnownTags()
    }

    @Test func testUseInfo() throws {
        let useInfo = UseInfo(asset: .btc, network: .mainnet)
        let envelope = useInfo.envelope
        #expect(useInfo.envelope.format() == """
        'BTC' [
            'network': 'MainNet'
        ]
        """)
        #expect(try useInfo == UseInfo(envelope: envelope))
    }
    
    @Test func testHDKey() throws {
        let bip39Seed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
        let masterKey = try HDKey(bip39Seed: bip39Seed)
        
        let masterEnvelope = masterKey.envelope
        #expect(masterEnvelope.format() == """
        Bytes(33) [
            'isA': 'BIP32Key'
            'isA': 'MasterKey'
            'isA': 'PrivateKey'
            'asset': 'BTC' [
                'network': 'MainNet'
            ]
            'chainCode': Bytes(32)
        ]
        """)
        let masterKey2 = try HDKey(envelope: masterEnvelope)
        #expect(masterKey == masterKey2)

        let absolutePath = DerivationPath(string: "m/48h/0h/0h/2h/0/0")!
        var childKey = try HDKey(parent: masterKey, derivedKeyType: .public, childDerivationPath: absolutePath)
        childKey.name = "This is the key name."
        childKey.note = "This is the key note."
        
        let childEnvelope = childKey.envelope
        #expect(childEnvelope.format() == """
        Bytes(33) [
            'isA': 'BIP32Key'
            'isA': 'PublicKey'
            'asset': 'BTC' [
                'network': 'MainNet'
            ]
            'chainCode': Bytes(32)
            'hasName': "This is the key name."
            'note': "This is the key note."
            'parent': keypath(Map)
            'parentFingerprint': 3912704230
        ]
        """)
        let childKey2 = try HDKey(envelope: childEnvelope)
        #expect(childKey == childKey2)
    }
}
