import XCTest
import BCFoundation
import WolfBase

let globalFormatContext = {
    addKnownFunctionExtensions()
    return FormatContext(tags: globalTags, functions: globalFunctions, parameters: globalParameters)
}()

class RequestTests: XCTestCase {
    static let mnemonic = "fly mule excess resource treat plunge nose soda reflect adult ramp planet"
    static let seed = Seed(bip39: BIP39(mnemonic: mnemonic)!)
    static let id = CID(‡"c66be27dbad7cd095ca77647406d07976dc0f35f0d4d654bb0e96dd227a1e9fc")!
    static let note = "Test"
    
    static let masterKey = try! HDKey(seed: seed)
    static let masterKeyFingerprint = masterKey.keyFingerprint.hex

    static let validPSBT = PSBT(base64: "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA")!

    func testSeedRequest() throws {
        let body = try SeedRequestBody(seedDigest: Self.seed.identityDigest)
        let request = TransactionRequest(id: Self.id, body: body, note: Self.note)
        let ur = request.ur
        let expectedURString = "ur:envelope/lstpsptpcstptktaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsietpsplftpsptpcstpttcsietpsptpsolftpsptpcstptdcssptpsptpcstaadeshdcxzmoycylumhmdgwspnyvadaktnsoycwmyaodihgftdllugltphlmtutytadosdwwdtpsptpsolftpsptpsgaatpsptpcsieghihjkjylynldndi"
        XCTAssertEqual(ur.string, expectedURString)
        
        let expectedFormat = """
        request(CID(c66be27d)) [
            body: «getSeed» [
                ❰seedDigest❱: seed-digest(Bytes(32))
            ]
            note: "Test"
        ]
        """
        let envelope = try request.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let request2 = try TransactionRequest(ur: ur)
        XCTAssertEqual(request2, request)
    }
    
    func testSeedResponse() throws {
        let response = TransactionResponse(id: Self.id, body: Self.seed)
        let ur = response.ur
        let expectedURString = "ur:envelope/lftpsptpcstptitaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsihtpsptpcstaaddwoyadgdhkwzdtfthptokigtvwnnjsqzcxknsktdvontidox"
        XCTAssertEqual(ur.string, expectedURString)
        
        let expectedFormat = """
        response(CID(c66be27d)) [
            result: crypto-seed(Map)
        ]
        """
        let envelope = try response.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let response2 = try TransactionResponse(ur: ur)
        XCTAssertEqual(response2, response)
    }
    
    func testKeyRequest() throws {
        let path = DerivationPath(string: "\(Self.masterKeyFingerprint)/48'/0'/0'/2'")!
        let useInfo = UseInfo(asset: .btc, network: .testnet)
        let body = KeyRequestBody(keyType: .private, path: path, useInfo: useInfo)
        let request = TransactionRequest(id: Self.id, body: body, note: Self.note)
        let ur = request.ur
        let expectedURString = "ur:envelope/lstpsptpcstptktaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgaatpsptpcsieghihjkjytpsptpsolftpsptpsgcsietpsplstpsptpcstpttcsihtpsptpsolftpsptpcstptdcssbtpsptpcstaadehoyaoadtpsptpsolftpsptpcstptdcssotpsptpcstaaddyoeadlocsdyykaeykaeykaoykaocyhngrmuwzosmkahrf"
        XCTAssertEqual(ur.string, expectedURString)
        
        let expectedFormat = """
        request(CID(c66be27d)) [
            body: «getKey» [
                ❰derivationPath❱: crypto-keypath(Map)
                ❰useInfo❱: crypto-coin-info(Map)
            ]
            note: "Test"
        ]
        """
        let envelope = try request.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let request2 = try TransactionRequest(ur: ur)
        XCTAssertEqual(request2, request)
    }
    
    func testKeyResponse() throws {
        let path = DerivationPath(string: "\(Self.masterKeyFingerprint)/48'/0'/0'/2'")!
        let useInfo = UseInfo(asset: .btc, network: .testnet)
        let masterKey = try HDKey(seed: Self.seed, useInfo: useInfo)
        let key = try HDKey(parent: masterKey, childDerivationPath: path)
        let response = TransactionResponse(id: Self.id, body: key)
        let ur = response.ur
        let expectedURString = "ur:envelope/lftpsptpcstptitaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsihtpsptpcstaaddlolaoykaxhdclaevytktyhkfthkglbyzehflpenbsfxbkvlvyghtsondrzeskswvoclemaswtzodlhnaahdcxlejtimcnrlbtdemdoereyaqzprkpndbdgwfzflqdbzkohgzobycxcnvabaosbglfahtaadehoyaoadamtaaddyotadlocsdyykaeykaeykaoykaocyhngrmuwzaxaaaycynewncnlbvalntlwd"
        XCTAssertEqual(ur.string, expectedURString)

        let expectedFormat = """
        response(CID(c66be27d)) [
            result: crypto-hdkey(Map)
        ]
        """
        let envelope = try response.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let response2 = try TransactionResponse(ur: ur)
        XCTAssertEqual(response2, response)
    }
    
    func testDerivationRequest() throws {
        let path = DerivationPath(string: "48'/0'/0'/2'")!
        let body = KeyRequestBody(keyType: .private, path: path, useInfo: .init(asset: .btc, network: .testnet))
        let request = TransactionRequest(id: Self.id, body: body, note: Self.note)
        let ur = request.ur
        let expectedURString = "ur:envelope/lstpsptpcstptktaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsietpsplstpsptpcstpttcsihtpsptpsolftpsptpcstptdcssbtpsptpcstaadehoyaoadtpsptpsolftpsptpcstptdcssotpsptpcstaaddyoyadlocsdyykaeykaeykaoyktpsptpsolftpsptpsgaatpsptpcsieghihjkjygtiodkdw"
        XCTAssertEqual(ur.string, expectedURString)

        let expectedFormat = """
        request(CID(c66be27d)) [
            body: «getKey» [
                ❰derivationPath❱: crypto-keypath(Map)
                ❰useInfo❱: crypto-coin-info(Map)
            ]
            note: "Test"
        ]
        """
        let envelope = try request.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let request2 = try TransactionRequest(ur: ur)
        XCTAssertEqual(request2, request)
    }
    
    func testPSBTSigningRequest() throws {
        let body = PSBTSignatureRequestBody(psbt: Self.validPSBT, isRawPSBT: false)
        let request = TransactionRequest(id: Self.id, body: body, note: Self.note)
        let ur = request.ur
        let expectedURString = "ur:envelope/lstpsptpcstptktaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsietpsplftpsptpcstpttcsiytpsptpsolftpsptpcstptdcssntpsptpcstaadenhkaodnjojkidjyzmadaekpaoaeaeaeaddslyjsemckurwzlpwlempmwyoxqdkgksaebnahiysbqdpmieiechbwsgfwchcwynaeaeaeaeaezezmzmzmaoteurykahaeaeaeaecfkoptbbtisknlaxskrdsalnlthnwlbstlcloxiyhtosihcxlopsaevyykahaeaeaeaechptbbecfevavlfrlsdwflahbsdktewyrhfnnsaxmwlustltqddmbwaeaeadaezconadadaeaeaeaeadaoldotstckpygtcxvtemcwrkoxsfinmyoemdsofgftzsdmeslblpeosfrpdlmdiovwadaeaeaechcmaebbrncsttgmptpfbgaxntpefsosuegwgueennwprhlpzmzmzmzmlnyapkfxoscazmbbfdldftgubkjpemwsjefgayrkprutdpadjsvaftwpimfdmhqzadaeaeaechcmaebbzefmnnwnosfewljytaaossechkfxpysbeeryguguzmzmzmzmaoaesawmbdaeaeaeaecfkoptbblptkwnaslbtavtayrkeepejonsidcfkgetmslefdlopsjpzeyagldwaeaeaechptbbeomsdardclwstbdrstguptrftiiotbstolotntahltaofldyfyaocxdibgrncpvtdibsesgwhflsbyuokeptolldjoroaoheutfrdkaodtwtlbleheftdkaocxadluettsuotebbvdeesodijetbzofzynjkeyhpssrdoyfyspaetdwzwtdpprkohhadclaxtdvyhfjymwcwpmgenliajpsbltvylpjnengmhnjnmkhfdlvlnshynnkbfpfhclahaofddyfeaoclaettdnlpdplpuotahstdykwkpyiyamghurjtwesfkkgsbneotohhsraszmreztvwlgaocxioeolemnbachdasemszocylopehkykckfyvedahpcxcmkelnlraxceahttwzhkdradclaocnrldnwywtmthlbernatkswswptbctsgswylnygloyineseolajkfyieyagwdrqdaeaeaeaeaeaeaetpsptpsolftpsptpsgaatpsptpcsieghihjkjyrsdrjkrf"
        XCTAssertEqual(ur.string, expectedURString)

        let expectedFormat = """
        request(CID(c66be27d)) [
            body: «signPSBT» [
                ❰psbt❱: crypto-psbt(Bytes(555))
            ]
            note: "Test"
        ]
        """
        let envelope = try request.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let request2 = try TransactionRequest(ur: ur)
        XCTAssertEqual(request2, request)
    }
    
    func testPSBTResponse() throws {
        let response = TransactionResponse(id: Self.id, body: Self.validPSBT)
        let ur = response.ur
        let expectedURString = "ur:envelope/lftpsptpcstptitaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsihtpsptpcstaadenhkaodnjojkidjyzmadaekpaoaeaeaeaddslyjsemckurwzlpwlempmwyoxqdkgksaebnahiysbqdpmieiechbwsgfwchcwynaeaeaeaeaezezmzmzmaoteurykahaeaeaeaecfkoptbbtisknlaxskrdsalnlthnwlbstlcloxiyhtosihcxlopsaevyykahaeaeaeaechptbbecfevavlfrlsdwflahbsdktewyrhfnnsaxmwlustltqddmbwaeaeadaezconadadaeaeaeaeadaoldotstckpygtcxvtemcwrkoxsfinmyoemdsofgftzsdmeslblpeosfrpdlmdiovwadaeaeaechcmaebbrncsttgmptpfbgaxntpefsosuegwgueennwprhlpzmzmzmzmlnyapkfxoscazmbbfdldftgubkjpemwsjefgayrkprutdpadjsvaftwpimfdmhqzadaeaeaechcmaebbzefmnnwnosfewljytaaossechkfxpysbeeryguguzmzmzmzmaoaesawmbdaeaeaeaecfkoptbblptkwnaslbtavtayrkeepejonsidcfkgetmslefdlopsjpzeyagldwaeaeaechptbbeomsdardclwstbdrstguptrftiiotbstolotntahltaofldyfyaocxdibgrncpvtdibsesgwhflsbyuokeptolldjoroaoheutfrdkaodtwtlbleheftdkaocxadluettsuotebbvdeesodijetbzofzynjkeyhpssrdoyfyspaetdwzwtdpprkohhadclaxtdvyhfjymwcwpmgenliajpsbltvylpjnengmhnjnmkhfdlvlnshynnkbfpfhclahaofddyfeaoclaettdnlpdplpuotahstdykwkpyiyamghurjtwesfkkgsbneotohhsraszmreztvwlgaocxioeolemnbachdasemszocylopehkykckfyvedahpcxcmkelnlraxceahttwzhkdradclaocnrldnwywtmthlbernatkswswptbctsgswylnygloyineseolajkfyieyagwdrqdaeaeaeaeaeaeaedlemroae"
        XCTAssertEqual(ur.string, expectedURString)

        let expectedFormat = """
        response(CID(c66be27d)) [
            result: crypto-psbt(Bytes(555))
        ]
        """
        let envelope = try response.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let response2 = try TransactionResponse(ur: ur)
        XCTAssertEqual(response2, response)
    }
    
    func testOutputDescriptorRequest() throws {
        let useInfo = UseInfo(asset: .btc, network: .testnet)
        let body = OutputDescriptorRequestBody(name: "Name", useInfo: useInfo, challenge: ‡"fcb2fc04b4e352dd10cfe6bc90fe80a8")
        let request = TransactionRequest(id: Self.id, body: body, note: Self.note)
        let ur = request.ur
        let expectedURString = "ur:envelope/lstpsptpcstptktaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsietpsplrtpsptpcstpttcsiotpsptpsolftpsptpcstptdcstotpsptpcsieglhsjnihtpsptpsolftpsptpcstptdcssbtpsptpcstaadehoyaoadtpsptpsolftpsptpcstptdcstktpsptpcsgdztprztaaqzvlgmutbetkvarfmhzelapdtpsptpsolftpsptpsgaatpsptpcsieghihjkjylndewlkb"
        XCTAssertEqual(ur.string, expectedURString)

        let expectedFormat = """
        request(CID(c66be27d)) [
            body: «getOutputDescriptor» [
                ❰challenge❱: Bytes(16)
                ❰name❱: "Name"
                ❰useInfo❱: crypto-coin-info(Map)
            ]
            note: "Test"
        ]
        """
        let envelope = try request.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let request2 = try TransactionRequest(ur: ur)
        XCTAssertEqual(request2, request)
    }
    
    func testOutputDescriptorResponse() throws {
        let outputDescriptor = try OutputDescriptor("pkh([37b5eed4/44'/0'/0']xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu/<0;1>/*)")
        let challengeSignature = ‡"740cafaba9d257660e9244870cf50b5f47cbc67932e9a9fe0fa94cb36d38193c"
        let body = OutputDescriptorResponseBody(descriptor: outputDescriptor, challengeSignature: challengeSignature)
        let response = TransactionResponse(id: Self.id, body: body)
        let ur = response.ur
        let expectedURString = "ur:envelope/lftpsptpcstptitaadethdcxswjevokirdtssnashhoskoflfzjnatmsjnrtwfhebtgtihgrpfwljntddioywlzttpsptpsolftpsptpsgcsihtpsptpcstaadwklfksnljojeisdehpeoemidecihihieeedleeeedidldydidldydihlksjokpidenfxjtgyjeinkogofefdesidguidhghfhgiyfygsfxjyiniogrgriojtguhgflhshfgugmkkfxidgleygyglfwgeknkpkofdghehkogogyjoiogujohkehglinhfkojlihglfekphfktjeemeeetfxjtesfleogljyidgyfwehhsflfljkfegsemhshkfejtimhfhgioimimesjyihiykpdlfndyfrehfmdldrdtcnkokskkiakkeeihishdcxjybnpepypttdhgiybamofyltbnykbdheflsbswkkeywlptzebsptgsqdjnetcffnmhdyaycp"
        XCTAssertEqual(ur.string, expectedURString)

        let expectedFormat = """
        response(CID(c66be27d)) [
            result: output-descriptor-response(["pkh([37b5eed4/44'/0'/0']xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu/<0;1>/*)#vxycy4eh", Bytes(32)])
        ]
        """
        let envelope = try response.envelope.checkEncoding()
        XCTAssertEqual(envelope.format(context: globalFormatContext), expectedFormat)

        let response2 = try TransactionResponse(ur: ur)
        XCTAssertEqual(response2, response)
    }
}
