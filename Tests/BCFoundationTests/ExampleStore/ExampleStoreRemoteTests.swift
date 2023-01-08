import BCFoundation
import WolfBase
import XCTest

class ExampleStoreRemoteTests: XCTestCase {
    override class func setUp() {
        addKnownFunctionExtensions()
        addKnownTags()
    }
    
    func testStoreRemote() throws {
        let exampleStore = ExampleStore()

        // Alice stores a share
        let alicePrivateKey = PrivateKeyBase()
        let alicePayload1 = ‡"cafebabe"
        var aliceReceipt1: Receipt!
        do {
            let request = StoreShareRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, payload: alicePayload1)
            let response = exampleStore.handleRequest(request)
            aliceReceipt1 = try response.result(Receipt.self)
        }

        // Bob stores a share
        let bobPrivateKey = PrivateKeyBase()
        let bobPayload1 = ‡"deadbeef"
        var bobReceipt1: Receipt!
        do {
            let request = StoreShareRequestBody.makeRequest(accountPrivateKey: bobPrivateKey, payload: bobPayload1)
            let response = exampleStore.handleRequest(request)
            bobReceipt1 = try response.result(Receipt.self)
        }
        
        // Alice retrieves her share
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, receipts: [aliceReceipt1])
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.result(Data.self), alicePayload1)
        }
        
        // Bob retrieves his share
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: bobPrivateKey, receipts: [bobReceipt1])
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.result(Data.self), bobPayload1)
        }

        // Alice stores a second share
        let alicePayload2 = ‡"cafef00d"
        var aliceReceipt2: Receipt!
        do {
            let request = StoreShareRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, payload: alicePayload2)
            let response = exampleStore.handleRequest(request)
            aliceReceipt2 = try response.result(Receipt.self)
        }

        // Alice retrieves her second share
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, receipts: [aliceReceipt2])
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.result(Data.self), alicePayload2)
        }
        
        // Alice retrieves both her shares identified only by her public key.
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(Set(try response.results(Data.self)), Set([alicePayload1, alicePayload2]))
        }
        
        // Bob attempts to retrieve one of Alice's shares
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: bobPrivateKey, receipts: [aliceReceipt1])
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "userMismatch")
        }
        
        // Someone attempts to retrieve all shares from a nonexistent account
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: PrivateKeyBase())
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "unknownPublicKey")
        }

        // Alice stores a share she's previously stored (idempotent)
        do {
            let request = StoreShareRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, payload: alicePayload1)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.result(Receipt.self), aliceReceipt1)
        }
        
        // Alice deletes one of her shares
        do {
            let request = DeleteSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, receipts: [aliceReceipt1])
            let response = exampleStore.handleRequest(request)
            XCTAssertTrue(try response.isResultOK())
        }
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(Set(try response.results(Data.self)), Set([alicePayload2]))
        }
        
        // Alice attempts to delete a share she already deleted (idempotent).
        do {
            let request = DeleteSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey, receipts: [aliceReceipt1])
            let response = exampleStore.handleRequest(request)
            XCTAssertTrue(try response.isResultOK())
        }
        
        // Bob adds a fallback contact method
        do {
            let request = UpdateFallbackRequestBody.makeRequest(accountPrivateKey: bobPrivateKey, fallback: "bob@example.com")
            let response = exampleStore.handleRequest(request)
            XCTAssertTrue(try response.isResultOK())
        }
        do {
            let request = RetrieveFallbackRequestBody.makeRequest(accountPrivateKey: bobPrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.result(String.self), "bob@example.com")
        }
        
        // Alice has never set her fallback contact method
        do {
            let request = RetrieveFallbackRequestBody.makeRequest(accountPrivateKey: alicePrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "noFallback")
        }

        // Someone attempts to retrieve the fallback for a nonexistent account
        do {
            let request = RetrieveFallbackRequestBody.makeRequest(accountPrivateKey: PrivateKeyBase())
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "unknownPublicKey")
        }
        
        // Alice updates her public key to a new one
        let alicePrivateKey2 = PrivateKeyBase()
        do {
            let request = UpdatePublicKeyRequestBody.makeRequest(privateKey: alicePrivateKey, newPrivateKey: alicePrivateKey2)
            let response = exampleStore.handleRequest(request)
            XCTAssertTrue(try response.isResultOK())
        }
        
        // Alice can no longer retrieve her shares using the old public key
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "unknownPublicKey")
        }
        
        // Alice must now use her new public key
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: alicePrivateKey2)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(Set(try response.results(Data.self)), Set([alicePayload2]))
        }
        
        // Bob has lost his public key, so he wants to replace it with a new one
        let bobPrivateKey2 = PrivateKeyBase()
        
        // Bob requests transfer using an incorrect fallback
        do {
            let request = FallbackTransferRequestBody.makeRequest(fallback: "wrong@example.com", newPrivateKey: bobPrivateKey2)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "invalidFallback")
        }
        
        // Bob requests a transfer using the correct fallback
        do {
            let request = FallbackTransferRequestBody.makeRequest(fallback: "bob@example.com", newPrivateKey: bobPrivateKey2)
            let response = exampleStore.handleRequest(request)
            // Here the store must initiate asyncronously using the fallback to verify the
            // user's intent to change their key and only change it if the verification
            // succeeds.
            XCTAssertEqual(try response.result(Envelope.KnownValue.self), .processing)
        }
        
        // Bob never confirms the transfer request, but instead decides to delete his entire account
        do {
            let request = DeleteAccountRequestBody.makeRequest(accountPrivateKey: bobPrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssert(try response.isResultOK())
        }
        
        // Attempting to retrieve his share now returns an error
        do {
            let request = RetrieveSharesRequestBody.makeRequest(accountPrivateKey: bobPrivateKey, receipts: [bobReceipt1])
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "unknownPublicKey")
        }
        
        // Attempting to retrieve his fallback now returns an error
        do {
            let request = RetrieveFallbackRequestBody.makeRequest(accountPrivateKey: bobPrivateKey)
            let response = exampleStore.handleRequest(request)
            XCTAssertEqual(try response.error(String.self), "unknownPublicKey")
        }
    }
}
