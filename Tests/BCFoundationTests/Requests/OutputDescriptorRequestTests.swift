import XCTest
import BCFoundation
import WolfBase

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
        let request = TransactionRequest(id: slotID, body: body, note: note)
        
        //print(request.envelope.format)
        
        return request.ur
    }
    
    func makeResponse(to requestUR: UR, descriptor: OutputDescriptor, masterKey: HDKey) throws -> UR {
        let request = try TransactionRequest(ur: requestUR)
        guard let requestBody = try request.parseBody() as? OutputDescriptorRequestBody else {
            throw GeneralError("Not a request for an output descriptor.")
        }
        
        let signingKey = descriptor.hdKey(keyType: .private, chain: .external, addressIndex: 0, privateKeyProvider: { key in
            try HDKey(parent: masterKey, childDerivationPath: key.parent)
        })!
        
        let challengeSignature = signingKey.ecPrivateKey!.ecdsaSign(requestBody.challenge)
        let result = OutputDescriptorResponseBody(descriptor: descriptor, challengeSignature: challengeSignature)
        let response = TransactionResponse(id: request.id, result: result)
        return response.envelope.ur
    }
    
    func validateResponse(_ responseUR: UR) throws {
        let envelope = try Envelope(ur: responseUR)
        let response = try TransactionResponse(envelope)
        guard let responseBody = try response.parseResult() as? OutputDescriptorResponseBody else {
            throw GeneralError("Not a response for an output descriptor.")
        }
        guard responseBody.descriptor.baseKey != nil else {
            throw GeneralError("Could not retrieve public key from returned descriptor.")
        }
        guard let validationKey = responseBody.descriptor.hdKey(chain: .external, addressIndex: 0) else {
            throw GeneralError("Could not derive validation key from returned descriptor.")
        }
        let ecValidationKey = validationKey.ecPublicKey
        guard ecValidationKey.verify(signature: responseBody.challengeSignature, message: challenge) else {
            throw GeneralError("Invalid challenge signature.")
        }
    }
}
