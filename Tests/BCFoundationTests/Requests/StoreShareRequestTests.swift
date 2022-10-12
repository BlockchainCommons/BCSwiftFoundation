import XCTest
import BCFoundation
import WolfBase

public struct StoreRequestBody: TransactionRequestBody {
    public static var function: FunctionIdentifier = "store"
    public let controller: PublicKeyBase
    public let payload: Data

    public init(controller: PublicKeyBase, payload: CBOREncodable) {
        self.controller = controller
        self.payload = payload.cborEncode
    }
    
    public init(_ envelope: Envelope) throws {
        self.controller = try envelope.extractObject(PublicKeyBase.self, forParameter: "controller")
        self.payload = try envelope.extractObject(Data.self, forParameter: "payload")
    }
    
    public var envelope: Envelope {
        try! Envelope(function: Self.function)
            .addAssertion(.parameter("controller", value: controller))
            .addAssertion(.parameter("payload", value: payload))
    }
}

class StoreShareRequestTests: XCTestCase {
    override class func setUp() {
        addKnownTags()
        addKnownFunctionExtensions()
    }

    // ExampleStore has issued a known public key. Alice's request is going to be encrypted to ExampleStore's public key to ensure that only they can act on it.
    static let exampleStorePrivateKeys = PrivateKeyBase()
    static let exampleStorePublicKeys = exampleStorePrivateKeys.publicKeys

    func makeStoreShareRequest() throws -> String {
        let transactionID = CID(‡"b94cdf7773a6dd4a40c959e2e4c611503851a67ac477361321ccec7670b361b8")!
        
        // Alice has a seed she wants to back up.
        let aliceSeed = Seed()
        
        // She shards her seed into a set of 2-of-3 SSKR shares.
        let aliceShares = try SSKRGenerate(groupThreshold: 1, groups: [.init(threshold: 2, count: 3)], secret: aliceSeed.data).flatMap { $0 }
        
        // Alice is going to store one of her shares with ExampleStore.
        let share = aliceShares.first!
        
        // Alice has a private key, and she's going to use the public key to identify herself as the controller of her share
        let alicePrivateKeys = PrivateKeyBase()
        let alicePublicKeys = alicePrivateKeys.publicKeys
        
        // Alice composes her request
        let body = StoreRequestBody(controller: alicePublicKeys, payload: share)
        XCTAssertEqual(body.envelope.format,
        """
        «"store"» [
            ❰"controller"❱: PublicKeyBase
            ❰"payload"❱: Data
        ]
        """)
        let request = TransactionRequest(id: transactionID, body: body).envelope()
        XCTAssertEqual(request.format,
        """
        request(CID(b94cdf7773a6dd4a40c959e2e4c611503851a67ac477361321ccec7670b361b8)) [
            body: «"store"» [
                ❰"controller"❱: PublicKeyBase
                ❰"payload"❱: Data
            ]
        ]
        """)
        
        // Sign then encrypt the request
        
        let signedRequest = request
            .wrap()
            .sign(with: alicePrivateKeys)
        XCTAssertEqual(signedRequest.format,
        """
        {
            request(CID(b94cdf7773a6dd4a40c959e2e4c611503851a67ac477361321ccec7670b361b8)) [
                body: «"store"» [
                    ❰"controller"❱: PublicKeyBase
                    ❰"payload"❱: Data
                ]
            ]
        } [
            verifiedBy: Signature
        ]
        """)
        
        let encryptedRequest = try signedRequest
            .encryptSubject(to: Self.exampleStorePublicKeys)
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
        let decryptedRequest = try receivedEnvelope.decrypt(to: Self.exampleStorePrivateKeys).unwrap()
        
        // Next it parses the request
        let receivedRequest = try TransactionRequest(StoreRequestBody.self, decryptedRequest)
        let receivedBody = receivedRequest.body as! StoreRequestBody
        
        // Now it verifies Alice's signature
        let controllerPublicKeys = receivedBody.controller
        try receivedEnvelope.verifySignature(from: controllerPublicKeys)
        let receivedPayload = receivedBody.payload
        
        // Now it can store Alice's share
        let record = (controllerPublicKeys, receivedPayload)
        print(record)
    }
}
