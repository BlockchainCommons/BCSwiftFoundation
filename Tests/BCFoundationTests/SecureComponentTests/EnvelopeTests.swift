import XCTest
import BCFoundation
import WolfBase

fileprivate let plaintext = "Some mysteries aren't meant to be solved.".utf8Data

fileprivate let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
fileprivate let aliceProfile = Profile(aliceSeed, salt: "Salt")
fileprivate let alicePeer = aliceProfile.peer

fileprivate let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
fileprivate let bobProfile = Profile(bobSeed, salt: "Salt")
fileprivate let bobPeer = bobProfile.peer

fileprivate let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
fileprivate let carolProfile = Profile(carolSeed, salt: "Salt")
fileprivate let carolPeer = carolProfile.peer

class EnvelopeTests: XCTestCase {
    func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let envelope = Envelope(plaintext: plaintext)
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)
        // Bob reads the message.
        XCTAssertEqual(receivedEnvelope.plaintext, plaintext)
    }

    func testSignedPlaintext() throws {
        // Alice sends a signed plaintext message to Bob.
        let envelope = Envelope(plaintext: plaintext, schnorrSigner: aliceProfile)
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)
        // Bob receives the message and verifies that it was signed by Alice.
        XCTAssertTrue(receivedEnvelope.hasValidSignature(from: alicePeer))
        // Confirm that it wasn't signed by Carol.
        XCTAssertFalse(receivedEnvelope.hasValidSignature(from: carolPeer))
        // Confirm that it was signed by Alice OR Carol.
        XCTAssertTrue(receivedEnvelope.hasValidSignatures(from: [alicePeer, carolPeer], threshold: 1))
        // Confirm that it was not signed by Alice AND Carol.
        XCTAssertFalse(receivedEnvelope.hasValidSignatures(from: [alicePeer, carolPeer], threshold: 2))

        // Bob reads the message.
        XCTAssertEqual(receivedEnvelope.plaintext, plaintext)
    }
    
    func testMultisignedPlaintext() throws {
        // Alice and Carol jointly send a signed plaintext message to Bob.
        let envelope = Envelope(plaintext: plaintext, schnorrSigners: [aliceProfile, carolProfile])
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob verifies the message was signed by both Alice and Carol.
        XCTAssertTrue(receivedEnvelope.hasValidSignatures(from: [alicePeer, carolPeer]))

        // Bob reads the message.
        XCTAssertEqual(receivedEnvelope.plaintext, plaintext)
    }
    
    func testSymmetricEncryption() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let envelope = Envelope(plaintext: plaintext, key: key)
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts and reads the message.
        XCTAssertEqual(receivedEnvelope.plaintext(with: key), plaintext)

        // Can't read with no key.
        XCTAssertNil(receivedEnvelope.plaintext)
        
        // Can't read with incorrect key.
        XCTAssertNil(receivedEnvelope.plaintext(with: SymmetricKey()))
    }
    
    func testSignThenEncrypt() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice signs a plaintext message, then encrypts it.
        let innerSignedEnvelope = Envelope(plaintext: plaintext, schnorrSigner: aliceProfile)
        let envelope = Envelope(inner: innerSignedEnvelope, key: key)
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts the outer envelope using the shared key.
        guard
            let innerEnvelope = receivedEnvelope.inner(with: key)
        else {
            XCTFail()
            return
        }
        // Bob validates Alice's signature.
        XCTAssertTrue(innerEnvelope.hasValidSignature(from: alicePeer))
        // Bob reads the message.
        XCTAssertEqual(innerEnvelope.plaintext, plaintext)
    }
    
    func testEncryptThenSign() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()
        
        // Alice encrypts a message, then signs it.
        let innerEncryptedEnvelope = Envelope(plaintext: plaintext, key: key)
        let envelope = Envelope(inner: innerEncryptedEnvelope, schnorrSigner: aliceProfile)
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob checks the signature of the outer envelope, then decrypts the inner envelope.
        guard
            receivedEnvelope.hasValidSignature(from: alicePeer),
            let plaintext = receivedEnvelope.inner?.plaintext(with: key)
        else {
            XCTFail()
            return
        }
        
        // Bob reads the message.
        XCTAssertEqual(plaintext, plaintext)
    }
    
    func testMultiRecipient() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let envelope = Envelope(plaintext: plaintext, recipients: [bobPeer, carolPeer])
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts and reads the message.
        XCTAssertEqual(receivedEnvelope.plaintext(for: bobProfile), plaintext)

        // Carol decrypts and reads the message.
        XCTAssertEqual(receivedEnvelope.plaintext(for: carolProfile), plaintext)

        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertNil(receivedEnvelope.plaintext(for: aliceProfile))
    }
    
    func testSignedMultiRecipient() throws {
        // Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
        let innerSignedEnvelope = Envelope(plaintext: plaintext, schnorrSigner: aliceProfile)
        let envelope = Envelope(inner: innerSignedEnvelope, recipients: [bobPeer, carolPeer])
        let ur = envelope.ur

//        print(envelope.taggedCBOR.diag)
//        print(envelope.taggedCBOR.dump)
//        print(envelope.ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedEnvelope = try Envelope(ur: ur)

        // Bob decrypts the outer envelope using his profile.
        guard
            let innerEnvelope = receivedEnvelope.inner(for: bobProfile)
        else {
            XCTFail()
            return
        }
        // Bob validates Alice's signature.
        XCTAssertTrue(innerEnvelope.hasValidSignature(from: alicePeer))
        // Bob reads the message.
        XCTAssertEqual(innerEnvelope.plaintext, plaintext)
    }
    
    func testSSKR() throws {
        // Dan has a cryptographic seed he wants to backup using a social recovery scheme.
        // The seed includes metadata he wants to back up also, making it too large to fit
        // into a basic SSKR share.
        var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        danSeed.name = "Dark Purple Aqua Love"
        danSeed.creationDate = try! Date("2021-02-24T00:00:00Z", strategy: .iso8601)
        danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

        // Dan splits the seed into a single group 2-of-3. This returns an array of arrays
        // of Envelope, the outer arrays representing SSKR groups and the inner array
        // elements each holding the encrypted seed and a single share.
        let envelopes = Envelope.split(plaintext: danSeed.taggedCBOR, groupThreshold: 1, groups: [(2, 3)])
        
        // Flattening the array of arrays gives just a single array of all the envelopes to be distributed.
        let sentEnvelopes = envelopes.flatMap { $0 }
        let sentURs = sentEnvelopes.map { $0.ur }
        
        // Dan sends one envelope to each of Alice, Bob, and Carol.
        
//        print(sentEnvelopes[0].taggedCBOR.diag)
//        print(sentEnvelopes[0].taggedCBOR.dump)
//        print(sentEnvelopes[0].ur)

        // ➡️ ☁️ ➡️

        // let aliceEnvelope = Envelope(ur: sentURs[0]) // UNRECOVERED
        let bobEnvelope = try Envelope(ur: sentURs[1])
        let carolEnvelope = try Envelope(ur: sentURs[2])

        // At some future point, Dan retrieves two of the three envelopes so he can recover his seed.
        let recoveredEnvelopes = [bobEnvelope, carolEnvelope]
        let recoveredSeed = try Seed(taggedCBOR: Envelope.plaintext(from: recoveredEnvelopes)!)

        // The recovered seed is correct.
        XCTAssertEqual(danSeed.data, recoveredSeed.data)
        XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
        XCTAssertEqual(danSeed.name, recoveredSeed.name)
        XCTAssertEqual(danSeed.note, recoveredSeed.note)
        
        // Attempting to recover with only one of the envelopes won't work.
        XCTAssertNil(Envelope.plaintext(from: [bobEnvelope]))
    }
}
