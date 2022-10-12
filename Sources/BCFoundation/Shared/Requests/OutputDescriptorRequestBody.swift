import Foundation
import WolfBase

public struct OutputDescriptorRequestBody: TransactionRequestBody {
    public static var function: FunctionIdentifier = .getOutputDescriptor
    public let name: String
    public let useInfo: UseInfo
    public let challenge: Data
    
    public init(name: String, useInfo: UseInfo, challenge: Data) {
        self.name = name
        self.useInfo = useInfo
        self.challenge = challenge
    }
}

public extension OutputDescriptorRequestBody {
    var envelope: Envelope {
        try! Envelope(function: .getOutputDescriptor)
            .addAssertion(.parameter(.challenge, value: challenge))
            .addAssertion(if: !name.isEmpty, .parameter(.name, value: name))
            .addAssertion(if: !useInfo.isDefault, .parameter(.useInfo, value: useInfo))
    }
    
    init(_ envelope: Envelope) throws {
        let name = (try? envelope.extractObject(String.self, forParameter: .name)) ?? ""
        let useInfo = (try? envelope.extractObject(UseInfo.self, forParameter: .useInfo)) ?? UseInfo()
        let challenge = try envelope.extractObject(Data.self, forParameter: .challenge)
        self.init(name: name, useInfo: useInfo, challenge: challenge)
    }
}
