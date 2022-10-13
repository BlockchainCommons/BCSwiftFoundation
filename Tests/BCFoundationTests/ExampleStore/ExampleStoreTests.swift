import BCFoundation
import WolfBase
import XCTest

class ExampleStoreTests: XCTestCase {
    func testStore() throws {
        let exampleStore = ExampleStore()

        // Alice stores a share
        let alicePublicKey = PrivateKeyBase().publicKeys
        let alicePayload1 = ‡"cafebabe"
        let aliceReceipt1 = try exampleStore.storeShare(publicKey: alicePublicKey, payload: alicePayload1)
        
        // Bob stores a share
        let bobPublicKey = PrivateKeyBase().publicKeys
        let bobPayload1 = ‡"deadbeef"
        let bobReceipt1 = try exampleStore.storeShare(publicKey: bobPublicKey, payload: bobPayload1)
        
        // Alice retrieves her share
        XCTAssertEqual(try exampleStore.retrieveShare(publicKey: alicePublicKey, receipt: aliceReceipt1), alicePayload1)
        
        // Bob retrieves his share
        XCTAssertEqual(try exampleStore.retrieveShare(publicKey: bobPublicKey, receipt: bobReceipt1), bobPayload1)
        
        // Alice stores a second share
        let alicePayload2 = ‡"cafef00d"
        let aliceReceipt2 = try exampleStore.storeShare(publicKey: alicePublicKey, payload: alicePayload2)

        // Alice retrieves her second share
        XCTAssertEqual(try exampleStore.retrieveShare(publicKey: alicePublicKey, receipt: aliceReceipt2), alicePayload2)
        
        // Alice retrieves both her shares identified only by her public key.
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).count, 2)
        
        // Bob attempts to retrieve one of Alice's shares
        XCTAssertThrowsError(try exampleStore.retrieveShare(publicKey: bobPublicKey, receipt: aliceReceipt1))
        
        // Someone attempts to retrieve all shares from a nonexistent account
        XCTAssertThrowsError(try exampleStore.retrieveShares(publicKey: PrivateKeyBase().publicKeys))
        
        // Alice stores a share she's previously stored (idempotent)
        XCTAssertEqual(try exampleStore.storeShare(publicKey: alicePublicKey, payload: alicePayload1), aliceReceipt1)
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).count, 2)
        
        // Alice deletes one of her shares
        try exampleStore.deleteShare(publicKey: alicePublicKey, receipt: aliceReceipt1)
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).count, 1)
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).first!.1, alicePayload2)
        
        // Alice attempts to delete a share she already deleted (idempotent).
        XCTAssertNoThrow(try exampleStore.deleteShare(publicKey: alicePublicKey, receipt: aliceReceipt1))

        // Bob adds a fallback contact method
        try exampleStore.updateFallback(publicKey: bobPublicKey, fallback: "bob@example.com")
        XCTAssertEqual(try exampleStore.retrieveFallback(publicKey: bobPublicKey), "bob@example.com")
        
        // Alice has never set her fallback contact method
        XCTAssertNil(try exampleStore.retrieveFallback(publicKey: alicePublicKey))

        // Someone attempts to retrieve the fallback for a nonexistent account
        XCTAssertThrowsError(try exampleStore.retrieveFallback(publicKey: PrivateKeyBase().publicKeys))
        
        // Alice updates her public key to a new one
        let alicePublicKey2 = PrivateKeyBase().publicKeys
        try exampleStore.updatePublicKey(old: alicePublicKey, new: alicePublicKey2)

        // Alice can no longer retrieve her shares using the old public key
        XCTAssertThrowsError(try exampleStore.retrieveShares(publicKey: alicePublicKey))

        // Alice must now use her new public key
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey2).count, 1)
        
        // Bob has lost his public key, so he wants to replace it with a new one
        let bobPublicKey2 = PrivateKeyBase().publicKeys

        // Bob requests transfer using an incorrect fallback
        XCTAssertThrowsError(try exampleStore.fallbackTransfer(fallback: "wrong@example.com", new: bobPublicKey2))
        
        // Bob requests a transfer using the correct fallback
        XCTAssertNoThrow(try exampleStore.fallbackTransfer(fallback: "bob@example.com", new: bobPublicKey2))

        // Bob never confirms the transfer request, but instead decides to delete his entire account
        exampleStore.deleteAccount(publicKey: bobPublicKey)

        // Attempting to retrieve his share now throws an error
        XCTAssertThrowsError(try exampleStore.retrieveShare(publicKey: bobPublicKey, receipt: bobReceipt1))

        // Attempting to retrieve his fallback now throws an error
        XCTAssertThrowsError(try exampleStore.retrieveFallback(publicKey: bobPublicKey))
    }
}
