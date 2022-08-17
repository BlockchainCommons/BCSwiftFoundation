import XCTest
import BCFoundation
import WolfBase

public struct GeneralError: LocalizedError {
    public let errorDescription: String?

    public init(_ errorDescription: String) {
        self.errorDescription = errorDescription
    }
}

class OutputDescriptorRequestTests: XCTestCase {
    let slotID = CID()
    let useInfo = UseInfo(asset: .btc, network: .testnet)
    let challenge = SecureRandomNumberGenerator.shared.data(count: 16)
    let accountNumber: UInt32 = 0
    
    override class func setUp() {
        addKnownFunctionExtensions()
    }

    func testOutputDescriptorRequest() throws {
        let masterKey = try HDKey(seed: Seed(), useInfo: useInfo)
        let bundle = OutputDescriptorBundle(masterKey: masterKey, network: useInfo.network, account: accountNumber)!
        let request = makeRequest()
        for descriptor in bundle.descriptors {
            let response = try makeResponse(to: request, descriptor: descriptor, masterKey: masterKey)
            try validateResponse(response)
        }
    }

    func makeRequest() -> UR {
        let name = "Bob's Slot"
        let note = "Alice is requesting an output descriptor from Bob."
        let body = OutputDescriptorRequestBody(name: name, useInfo: useInfo, challenge: challenge)
        let request = TransactionRequest(id: slotID, body: .outputDescriptor(body), note: note)
        
        //print(request.envelope.format)
        
        return request.ur
    }
    
    func makeResponse(to requestUR: UR, descriptor: OutputDescriptor, masterKey: HDKey) throws -> UR {
        let request = try TransactionRequest(ur: requestUR)
        guard case let .outputDescriptor(requestBody) = request.body else {
            throw GeneralError("Not a request for an output descriptor.")
        }
        
        let signingKey = descriptor.hdKey(keyType: .private, chain: .external, addressIndex: 0, privateKeyProvider: { key in
            try HDKey(parent: masterKey, childDerivationPath: key.parent)
        })!
        
        let challengeSignature = signingKey.ecPrivateKey!.ecdsaSign(message: requestBody.challenge)
        let body = OutputDescriptorResponseBody(descriptor: descriptor, challengeSignature: challengeSignature)
        let response = TransactionResponse(id: request.id, body: .outputDescriptor(body))
        return response.ur
    }
    
    func validateResponse(_ responseUR: UR) throws {
        let response = try TransactionResponse(ur: responseUR)
        guard case let .outputDescriptor(responseBody) = response.body else {
            throw GeneralError("Not a response for an output descriptor.")
        }
        guard responseBody.descriptor.baseKey != nil else {
            throw GeneralError("Could not retrieve public key from returned descriptor.")
        }
        guard let validationKey = responseBody.descriptor.hdKey(chain: .external, addressIndex: 0) else {
            throw GeneralError("Could not derive validation key from returned descriptor.")
        }
        let ecValidationKey = validationKey.ecPublicKey
        guard ecValidationKey.verify(message: challenge, signature: responseBody.challengeSignature) else {
            throw GeneralError("Invalid challenge signature.")
        }
    }
}
