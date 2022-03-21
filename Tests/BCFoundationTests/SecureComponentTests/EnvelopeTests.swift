import XCTest
import BCFoundation
import WolfBase

class EnvelopeTests: XCTestCase {
    static let plaintext = "Some mysteries aren't meant to be solved.".utf8Data

    static let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
    static let aliceIdentity = Identity(aliceSeed, salt: "Salt")
    static let alicePeer = Peer(identity: aliceIdentity)
    
    static let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
    static let bobIdentity = Identity(bobSeed, salt: "Salt")
    static let bobPeer = Peer(identity: bobIdentity)
    
    static let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
    static let carolIdentity = Identity(carolSeed, salt: "Salt")
    static let carolPeer = Peer(identity: carolIdentity)

    func testPlaintext() {
        // Alice sends a plaintext message to Bob.
        let envelope = Envelope(plaintext: Self.plaintext)
        
        // Bob reads the message.
        XCTAssertEqual(envelope.plaintext, Self.plaintext)
    }
    
    func testSignedPlaintext() {
        // Alice sends a signed plaintext message to Bob.
        let envelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
        
        // Bob receives the message and verifies that it was signed by Alice.
        XCTAssertTrue(envelope.hasValidSignature(from: Self.alicePeer))
        // Confirm that it wasn't signed by Carol.
        XCTAssertFalse(envelope.hasValidSignature(from: Self.carolPeer))

        // Bob reads the message.
        XCTAssertEqual(envelope.plaintext, Self.plaintext)
    }
    
    func testMultisignedPlaintext() {
        // Alice and Carol jointly send a signed plaintext message to Bob.
        let envelope = Envelope(plaintext: Self.plaintext, signers: [Self.aliceIdentity, Self.carolIdentity])
        
        // Bob receives the message and verifies that it was signed by both Alice and Carol.
        XCTAssertTrue(envelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer]))

        // Bob reads the message.
        XCTAssertEqual(envelope.plaintext, Self.plaintext)
    }
    
    func testThresholdMultisignedPlaintext() {
        // Alice sends a signed plaintext message to Bob.
        let envelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)

        // Bob receives the message and verifies that it was signed by either Alice or Carol.
        XCTAssertTrue(envelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer], threshold: 1))
        // Checking for both signatures fails.
        XCTAssertFalse(envelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer], threshold: 2))

        // Bob reads the message.
        XCTAssertEqual(envelope.plaintext, Self.plaintext)
    }
    
    func testSymmetricEncryption() {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let envelope = Envelope(plaintext: Self.plaintext, key: key)

        // Bob decrypts and reads the message.
        XCTAssertEqual(envelope.plaintext(with: key), Self.plaintext)

        // Can't read with no key.
        XCTAssertNil(envelope.plaintext)
        
        // Can't read with incorrect key.
        XCTAssertNil(envelope.plaintext(with: SymmetricKey()))
    }
    
    func testSignThenEncrypt() {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice signs a plaintext message, then encrypts it.
        let innerSignedEnvelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
        let envelope = Envelope(inner: innerSignedEnvelope, key: key)
        
        // Bob decrypts the outer envelope using the shared key.
        guard
            let innerEnvelope = envelope.inner(with: key)
        else {
            XCTFail()
            return
        }
        // Bob validates Alice's signature.
        XCTAssertTrue(innerEnvelope.hasValidSignature(from: Self.alicePeer))
        // Bob reads the message.
        XCTAssertEqual(innerEnvelope.plaintext, Self.plaintext)
    }
    
    func testEncryptThenSign() {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()
        
        // Alice encrypts a message, then signs it.
        let innerEncryptedEnvelope = Envelope(plaintext: Self.plaintext, key: key)
        let envelope = Envelope(inner: innerEncryptedEnvelope, signer: Self.aliceIdentity)
        
        // Bob checks the signature of the outer envelope, then decrypts the inner envelope.
        guard
            envelope.hasValidSignature(from: Self.alicePeer),
            let plaintext = envelope.inner?.plaintext(with: key)
        else {
            XCTFail()
            return
        }
        
        // Bob reads the message.
        XCTAssertEqual(plaintext, Self.plaintext)
    }
    
    func testMultiRecipient() {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let envelope = Envelope(plaintext: Self.plaintext, recipients: [Self.bobPeer, Self.carolPeer])
        
        // Bob decrypts and reads the message.
        XCTAssertEqual(envelope.plaintext(for: Self.bobIdentity), Self.plaintext)

        // Carol decrypts and reads the message.
        XCTAssertEqual(envelope.plaintext(for: Self.carolIdentity), Self.plaintext)

        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertNil(envelope.plaintext(for: Self.aliceIdentity))
    }
    
    func testSignedMultiRecipient() {
        // Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
        let innerSignedEnvelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
        let envelope = Envelope(inner: innerSignedEnvelope, recipients: [Self.bobPeer, Self.carolPeer])

        // Bob decrypts the outer envelope using his identity.
        guard
            let innerEnvelope = envelope.inner(for: Self.bobIdentity)
        else {
            XCTFail()
            return
        }
        // Bob validates Alice's signature.
        XCTAssertTrue(innerEnvelope.hasValidSignature(from: Self.alicePeer))
        // Bob reads the message.
        XCTAssertEqual(innerEnvelope.plaintext, Self.plaintext)
    }
    
    func testSSKR() throws {
        // Dan has a cryptographic seed he wants to backup using a social recovery scheme.
        // The seed includes metadata he wants to back up with the key, making it too large
        // to fit into a basic SSKR share.
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

        // Dan sends one envelope to each of Alice, Bob, and Carol.
        
        // let aliceEnvelope = sentEnvelopes[0] // UNRECOVERED
        let bobEnvelope = sentEnvelopes[1]
        let carolEnvelope = sentEnvelopes[2]
        
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
