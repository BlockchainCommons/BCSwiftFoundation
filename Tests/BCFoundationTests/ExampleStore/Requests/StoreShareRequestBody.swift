import Foundation
import BCFoundation

public struct StoreShareRequestBody: StoreRequestBody {
    public static var function: Function = "storeShare"
    public let publicKey: PublicKeyBase
    public let payload: Data

    public init(publicKey: PublicKeyBase, payload: Data) {
        self.publicKey = publicKey
        self.payload = payload
    }
    
    public init(_ envelope: Envelope) throws {
        guard try envelope.extractSubject(Function.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "publicKey")
        self.payload = try envelope.extractObject(Data.self, forParameter: "payload")
    }
    
    public var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter("publicKey", value: publicKey)
            .addParameter("payload", value: payload)
    }
    
    public static func makeRequest(accountPrivateKey: PrivateKeyBase, payload: Data, transactionID: CID? = nil) -> Envelope {
        let body = StoreShareRequestBody(publicKey: accountPrivateKey.publicKeys, payload: payload)
        return ExampleStore.makeRequest(body, accountPrivateKey: accountPrivateKey, transactionID: transactionID)
    }
}
