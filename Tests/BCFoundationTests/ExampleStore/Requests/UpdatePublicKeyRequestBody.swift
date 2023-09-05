import Foundation
import BCFoundation

public struct UpdatePublicKeyRequestBody: StoreRequestBody {
    public static var function: Function = "updatePublicKey"
    public let publicKey: PublicKeyBase
    public let newPublicKey: PublicKeyBase

    public init(publicKey: PublicKeyBase, newPublicKey: PublicKeyBase) {
        self.publicKey = publicKey
        self.newPublicKey = newPublicKey
    }
    
    public init(envelope: Envelope) throws {
        guard try envelope.extractSubject(Function.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "old")
        self.newPublicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "new")
    }
    
    public var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter("old", value: publicKey)
            .addParameter("new", value: newPublicKey)
    }
    
    public static func makeRequest(privateKey: PrivateKeyBase, newPrivateKey: PrivateKeyBase, transactionID: ARID? = nil) -> Envelope {
        let body = UpdatePublicKeyRequestBody(publicKey: privateKey.publicKeys, newPublicKey: newPrivateKey.publicKeys)
        return ExampleStore.makeRequest(body, accountPrivateKey: privateKey, transactionID: transactionID)
            .sign(with: newPrivateKey)
    }
}
