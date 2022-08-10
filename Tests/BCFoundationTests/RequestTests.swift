import XCTest
import BCFoundation
import WolfBase

class RequestTests: XCTestCase {
    static let mnemonic = "fly mule excess resource treat plunge nose soda reflect adult ramp planet"
    static let seed = Seed(bip39: BIP39(mnemonic: mnemonic)!)
    static let id = UUID(uuidString: "3B541437-5E3A-450B-8FE1-251CBC2B3FB5")!
    static let note = "Test"
    
    static let masterKey = try! HDKey(seed: seed)
    static let masterKeyFingerprint = masterKey.keyFingerprint.hex
    
    override class func setUp() {
        addKnownFunctionExtensions()
    }

    func testSeedRequest() throws {
        let body = try SeedRequestBody(digest: Self.seed.identityDigest)
        let request = TransactionRequest(id: Self.id, body: .seed(body), note: Self.note)
        let urString = "ur:crypto-request/otadtpdagdfrghbbemhyftfebdmyvydacerfdnfhreaotaadwkoyadtaaohdhdcxzmoycylumhmdgwspnyvadaktnsoycwmyaodihgftdllugltphlmtutytadosdwwdaxieghihjkjypdmncygy"
        XCTAssertEqual(request.ur.string, urString)
        
        let expectedFormat = """
        request(UUID(3B541437-5E3A-450B-8FE1-251CBC2B3FB5)) [
            body: «getSeed» [
                ❰seedDigest❱: CBOR
            ]
            note: "Test"
        ]
        """
        XCTAssertEqual(request.envelope.format, expectedFormat)
        
        let envelopeURString = "ur:envelope/lstpfntaaxcptpdagdfrghbbemhyftfebdmyvydacerfdnfhrelftpehtpfntpfrbstpehlftpfntaaxcxcsielftpehtpfntaaxclcssptpehtpfntaaohdhdcxzmoycylumhmdgwspnyvadaktnsoycwmyaodihgftdllugltphlmtutytadosdwwdlftpehtpfntpfraatpehtpfnieghihjkjynbmkflwf"
        XCTAssertEqual(request.envelope.ur.string, envelopeURString)

        let request2 = try TransactionRequest(ur: UR(urString: urString))
        XCTAssertEqual(request2.id, Self.id)
        XCTAssertEqual(request2.note, Self.note)
        guard case let .seed(body2) = request2.body else {
            XCTFail()
            return
        }
        XCTAssertEqual(body2.digest, Self.seed.identityDigest)
    }
    
    func testKeyRequest() throws {
        let path = DerivationPath(string: "\(Self.masterKeyFingerprint)/48'/0'/0'/2'")!
        let body = KeyRequestBody(keyType: .private, path: path, useInfo: .init(asset: .btc, network: .testnet))
        let request = TransactionRequest(id: Self.id, body: .key(body), note: Self.note)
        let urString = "ur:crypto-request/otadtpdagdfrghbbemhyftfebdmyvydacerfdnfhreaotaadykotadykaotaaddyoeadlocsdyykaeykaeykaoykaocyhngrmuwzaxtaadehoyaoadaxieghihjkjyhddsoees"
        XCTAssertEqual(request.ur.string, urString)
        
        let expectedFormat = """
        request(UUID(3B541437-5E3A-450B-8FE1-251CBC2B3FB5)) [
            body: «getKey» [
                ❰derivationPath❱: CBOR
                ❰useInfo❱: CBOR
            ]
            note: "Test"
        ]
        """
        XCTAssertEqual(request.envelope.format, expectedFormat)

        let envelopeURString = "ur:envelope/lstpfntaaxcptpdagdfrghbbemhyftfebdmyvydacerfdnfhrelftpehtpfntpfrbstpehlstpfntaaxcxcsihlftpehtpfntaaxclcssbtpehtpfntaadehoyaoadlftpehtpfntaaxclcssotpehtpfntaaddyoeadlocsdyykaeykaeykaoykaocyhngrmuwzlftpehtpfntpfraatpehtpfnieghihjkjytooxhyia"
        XCTAssertEqual(request.envelope.ur.string, envelopeURString)

        let request2 = try TransactionRequest(ur: UR(urString: urString))
        XCTAssertEqual(request2.id, Self.id)
        XCTAssertEqual(request2.note, Self.note)
        guard case let .key(body2) = request2.body else {
            XCTFail()
            return
        }
        XCTAssertEqual(body2.keyType, .private)
        XCTAssertEqual(body2.path, path)
    }
    
    func testDerivationRequest() throws {
        let path = DerivationPath(string: "48'/0'/0'/2'")!
        let body = KeyRequestBody(keyType: .private, path: path, useInfo: .init(asset: .btc, network: .testnet))
        let request = TransactionRequest(id: Self.id, body: .key(body), note: Self.note)
        let urString = "ur:crypto-request/otadtpdagdfrghbbemhyftfebdmyvydacerfdnfhreaotaadykotadykaotaaddyoyadlocsdyykaeykaeykaoykaxtaadehoyaoadaxieghihjkjyvlgswkwk"
        XCTAssertEqual(request.ur.string, urString)

        let expectedFormat = """
        request(UUID(3B541437-5E3A-450B-8FE1-251CBC2B3FB5)) [
            body: «getKey» [
                ❰derivationPath❱: CBOR
                ❰useInfo❱: CBOR
            ]
            note: "Test"
        ]
        """
        XCTAssertEqual(request.envelope.format, expectedFormat)

        let envelopeURString = "ur:envelope/lstpfntaaxcptpdagdfrghbbemhyftfebdmyvydacerfdnfhrelftpehtpfntpfrbstpehlstpfntaaxcxcsihlftpehtpfntaaxclcssotpehtpfntaaddyoyadlocsdyykaeykaeykaoyklftpehtpfntaaxclcssbtpehtpfntaadehoyaoadlftpehtpfntpfraatpehtpfnieghihjkjyuthfbkoe"
        XCTAssertEqual(request.envelope.ur.string, envelopeURString)
        
        let request2 = try TransactionRequest(ur: UR(urString: urString))
        XCTAssertEqual(request2.id, Self.id)
        XCTAssertEqual(request2.note, Self.note)
        guard case let .key(body2) = request2.body else {
            XCTFail()
            return
        }
        XCTAssertEqual(body2.keyType, .private)
        XCTAssertEqual(body2.path, path)
    }
    
    func testPSBTSigningRequest() throws {
        let validPSBT = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"
        let psbt = PSBT(base64: validPSBT)!
        let body = PSBTSignatureRequestBody(psbt: psbt, isRawPSBT: false)
        let request = TransactionRequest(id: Self.id, body: .psbtSignature(body), note: Self.note)
        let urString = "ur:crypto-request/otadtpdagdfrghbbemhyftfebdmyvydacerfdnfhreaotaadynoyadtaadenhkaodnjojkidjyzmadaekpaoaeaeaeaddslyjsemckurwzlpwlempmwyoxqdkgksaebnahiysbqdpmieiechbwsgfwchcwynaeaeaeaeaezezmzmzmaoteurykahaeaeaeaecfkoptbbtisknlaxskrdsalnlthnwlbstlcloxiyhtosihcxlopsaevyykahaeaeaeaechptbbecfevavlfrlsdwflahbsdktewyrhfnnsaxmwlustltqddmbwaeaeadaezconadadaeaeaeaeadaoldotstckpygtcxvtemcwrkoxsfinmyoemdsofgftzsdmeslblpeosfrpdlmdiovwadaeaeaechcmaebbrncsttgmptpfbgaxntpefsosuegwgueennwprhlpzmzmzmzmlnyapkfxoscazmbbfdldftgubkjpemwsjefgayrkprutdpadjsvaftwpimfdmhqzadaeaeaechcmaebbzefmnnwnosfewljytaaossechkfxpysbeeryguguzmzmzmzmaoaesawmbdaeaeaeaecfkoptbblptkwnaslbtavtayrkeepejonsidcfkgetmslefdlopsjpzeyagldwaeaeaechptbbeomsdardclwstbdrstguptrftiiotbstolotntahltaofldyfyaocxdibgrncpvtdibsesgwhflsbyuokeptolldjoroaoheutfrdkaodtwtlbleheftdkaocxadluettsuotebbvdeesodijetbzofzynjkeyhpssrdoyfyspaetdwzwtdpprkohhadclaxtdvyhfjymwcwpmgenliajpsbltvylpjnengmhnjnmkhfdlvlnshynnkbfpfhclahaofddyfeaoclaettdnlpdplpuotahstdykwkpyiyamghurjtwesfkkgsbneotohhsraszmreztvwlgaocxioeolemnbachdasemszocylopehkykckfyvedahpcxcmkelnlraxceahttwzhkdradclaocnrldnwywtmthlbernatkswswptbctsgswylnygloyineseolajkfyieyagwdrqdaeaeaeaeaeaeaeaxieghihjkjyialyeolb"
        XCTAssertEqual(request.ur.string, urString)

        let expectedFormat = """
        request(UUID(3B541437-5E3A-450B-8FE1-251CBC2B3FB5)) [
            body: «signPSBT» [
                ❰psbt❱: CBOR
            ]
            note: "Test"
        ]
        """
        XCTAssertEqual(request.envelope.format, expectedFormat)

        let envelopeURString = "ur:envelope/lstpfntaaxcptpdagdfrghbbemhyftfebdmyvydacerfdnfhrelftpehtpfntpfrbstpehlftpfntaaxcxcsiylftpehtpfntaaxclcssntpehtpfntaadenhkaodnjojkidjyzmadaekpaoaeaeaeaddslyjsemckurwzlpwlempmwyoxqdkgksaebnahiysbqdpmieiechbwsgfwchcwynaeaeaeaeaezezmzmzmaoteurykahaeaeaeaecfkoptbbtisknlaxskrdsalnlthnwlbstlcloxiyhtosihcxlopsaevyykahaeaeaeaechptbbecfevavlfrlsdwflahbsdktewyrhfnnsaxmwlustltqddmbwaeaeadaezconadadaeaeaeaeadaoldotstckpygtcxvtemcwrkoxsfinmyoemdsofgftzsdmeslblpeosfrpdlmdiovwadaeaeaechcmaebbrncsttgmptpfbgaxntpefsosuegwgueennwprhlpzmzmzmzmlnyapkfxoscazmbbfdldftgubkjpemwsjefgayrkprutdpadjsvaftwpimfdmhqzadaeaeaechcmaebbzefmnnwnosfewljytaaossechkfxpysbeeryguguzmzmzmzmaoaesawmbdaeaeaeaecfkoptbblptkwnaslbtavtayrkeepejonsidcfkgetmslefdlopsjpzeyagldwaeaeaechptbbeomsdardclwstbdrstguptrftiiotbstolotntahltaofldyfyaocxdibgrncpvtdibsesgwhflsbyuokeptolldjoroaoheutfrdkaodtwtlbleheftdkaocxadluettsuotebbvdeesodijetbzofzynjkeyhpssrdoyfyspaetdwzwtdpprkohhadclaxtdvyhfjymwcwpmgenliajpsbltvylpjnengmhnjnmkhfdlvlnshynnkbfpfhclahaofddyfeaoclaettdnlpdplpuotahstdykwkpyiyamghurjtwesfkkgsbneotohhsraszmreztvwlgaocxioeolemnbachdasemszocylopehkykckfyvedahpcxcmkelnlraxceahttwzhkdradclaocnrldnwywtmthlbernatkswswptbctsgswylnygloyineseolajkfyieyagwdrqdaeaeaeaeaeaeaelftpehtpfntpfraatpehtpfnieghihjkjydwvyzcwk"
        XCTAssertEqual(request.envelope.ur.string, envelopeURString)
//        print(request.envelope.ur.string)
//        print(request.envelope.format)

        let request2 = try TransactionRequest(ur: UR(urString: urString))
        XCTAssertEqual(request2.id, Self.id)
        XCTAssertEqual(request2.note, Self.note)
        guard case let .psbtSignature(body2) = request2.body else {
            XCTFail()
            return
        }
        XCTAssertEqual(body2.psbt, psbt)
    }
}
