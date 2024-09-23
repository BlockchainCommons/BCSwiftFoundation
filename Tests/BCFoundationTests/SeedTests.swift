//
//  SeedTests.swift
//  BCFoundationTests
//
//  Created by Wolf McNally on 9/15/21.
//

import XCTest
import BCFoundation
import WolfBase

class SeedTests: XCTestCase {
       
    func testBIP39() throws {
        let mnemonic = "surge mind remove galaxy define nephew surge helmet shine hurry voyage dawn"
        let bip39 = BIP39(mnemonic: mnemonic)!
        let seed = Seed(bip39: bip39)
        XCTAssertEqual(seed.data, ‡"da519ed7af739928b69357c5edf7d81b")
        XCTAssertEqual(seed.bip39.mnemonic, mnemonic)
        
        let key = try? HDKey(seed: seed)
        XCTAssertEqual(key?.base58, "xprv9s21ZrQH143K4TAgo7AZM1q8qTsQdfwMBeDHkzvbn7nadYjGPhqCzZrSTw72ykMRdUnUzvuJyfCH5W3NA7AK5MnWuBL8BYms3GSX7CHQth2")
    }
    
    func testAttachment() throws {
        let seed = Seed(
            data: ‡"82f32c855d3d542256180810797e0073",
            name: "Alice's Seed",
            note: "This is the note."
        )!
        let seedEnvelope = seed.envelope
            .addAttachment("Attachment Data V1", vendor: "com.example", conformsTo: "https://example.com/seed-attachment/v1")
            .addAttachment("Attachment Data V2", vendor: "com.example", conformsTo: "https://example.com/seed-attachment/v2")
        XCTAssertEqual(seedEnvelope.envelope.format(), """
        Bytes(16) [
            'isA': 'Seed'
            'attachment': {
                "Attachment Data V1"
            } [
                'conformsTo': "https://example.com/seed-attachment/v1"
                'vendor': "com.example"
            ]
            'attachment': {
                "Attachment Data V2"
            } [
                'conformsTo': "https://example.com/seed-attachment/v2"
                'vendor': "com.example"
            ]
            'hasName': "Alice's Seed"
            'note': "This is the note."
        ]
        """)
        XCTAssertEqual(try seedEnvelope.attachments().count, 2)
        XCTAssertEqual(try seedEnvelope.attachments(withVendor: "com.example").count, 2)
        let v1Attachment = try seedEnvelope.attachment(conformingTo: "https://example.com/seed-attachment/v1")
        XCTAssertEqual(try v1Attachment.attachmentPayload.format(),
        """
        "Attachment Data V1"
        """)
        XCTAssertEqual(try v1Attachment.attachmentVendor, "com.example")
        XCTAssertEqual(try v1Attachment.attachmentConformsTo, "https://example.com/seed-attachment/v1")
        
        let seedEnvelope2 = try seed.envelope.addAssertions(seedEnvelope.attachments())
        XCTAssertTrue(seedEnvelope2.isEquivalent(to: seedEnvelope))
    }
    
    func testOutputDescriptor() async throws {
        await addKnownTags()
        
        var seed = Seed(
            data: ‡"82f32c855d3d542256180810797e0073",
            name: "Alice's Seed",
            note: "This is the note."
        )!
        
        let masterKey = try HDKey(seed: seed)
        
        var desc = try AccountOutputType.wpkh.accountDescriptor(masterKey: masterKey, network: .testnet, account: 2)
        desc.name = "Alice's output descriptor"
        desc.note = "Output descriptor note"
        
        XCTAssertEqual(desc.sourceWithChecksum, "wpkh([55016b2f/84'/1'/2']xpub6BkiBzPzLUEo9F5n6N4CSKWzFeXdWaKGhYsVNXH8bqfbeAhdpvNeGhu2mP35cABAwDHNpHD5hmXfZcMSdpTUmAyCYnQggXkk9hwbTP9KRRB/<0;1>/*)#cf9l9nxt")
        XCTAssertEqual(desc.urString, "ur:output-descriptor/oxadisktjojeisdefzdydtaolytantjlonaxhdclaxoshhtirkpdcmihmuwkleonbzmtcfzovotnwteogolngamwrosfotoykbytlojohpaahdcxrkgumtwpoyflctgdadbbfptdehtloeplzmhfwsiminftutndpagyadkosbcthespamtantjooeadlncsghykadykaoykaocygoadjedlattantjooyadlslraewkadwklawkaycybtwtfhhlaxkscffpjziniaihdijkcxjlkpjyjokpjycxieihjkiajpinjojyjljpaakogwkpjyjokpjycxieihjkiajpinjojyjljpcxjtjljyihonprckkg")
        
        seed.outputDescriptor = desc
        
        XCTAssertEqual(seed.envelope.format(),
        """
        Bytes(16) [
            'isA': 'Seed'
            'hasName': "Alice's Seed"
            'note': "This is the note."
            'outputDescriptor': output-descriptor(Map)
        ]
        """)
        
        XCTAssert(desc.isDerivedFromSeed(seed))
    }
}
