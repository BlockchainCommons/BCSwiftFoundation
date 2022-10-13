import XCTest
import BCFoundation
import WolfBase

class StoreShareRequestTests: XCTestCase {
    override class func setUp() {
        addKnownTags()
        addKnownFunctionExtensions()
    }

    func makeStoreShareRequest() throws -> String {
        // Alice has a seed she wants to back up.
        let aliceSeed = Seed()
        
        // She shards her seed into a set of 2-of-3 SSKR shares.
        let aliceShares = try SSKRGenerate(groupThreshold: 1, groups: [.init(threshold: 2, count: 3)], secret: aliceSeed.data).flatMap { $0 }
        
        // Alice is going to store one of her shares with ExampleStore.
        let share = Data(aliceShares.first!.data)
        
        // Alice has a private key, and she's going to use the public key to identify herself as the controller of her share
        let alicePrivateKeys = PrivateKeyBase()
        
        let encryptedRequest = StoreShareRequestBody.makeRequest(accountPrivateKey: alicePrivateKeys, payload: share)
        XCTAssertEqual(encryptedRequest.format,
        """
        ENCRYPTED [
            hasRecipient: SealedMessage
            verifiedBy: Signature
        ]
        """)
        
        return encryptedRequest.ur.string
    }
    
    func test1() throws {
        let requestUR = try makeStoreShareRequest()
        // Alice -> ExampleStore
        
        let receivedEnvelope = try Envelope(urString: requestUR)
        
        // ExampleStore first decrypts the message. It will verify the signature later once it has parsed out Alice's public key.
        let decryptedRequest = try receivedEnvelope.decrypt(to: ExampleStore.privateKey).unwrap()
        
        // Next it parses the request
        let receivedRequest = try TransactionRequest(StoreShareRequestBody.self, decryptedRequest)
        let receivedBody = receivedRequest.body as! StoreShareRequestBody
        
        // Now it verifies Alice's signature
        let controllerPublicKeys = receivedBody.publicKey
        try receivedEnvelope.verifySignature(from: controllerPublicKeys)
        let receivedPayload = receivedBody.payload
        
        // Now it can store Alice's share
        let record = (controllerPublicKeys, receivedPayload)
        print(record)
    }
}
