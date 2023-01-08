import Foundation
import Envelope

public extension Envelope.FunctionIdentifier {
    static let getSeed = Envelope.FunctionIdentifier(100, "getSeed")
    static let getKey = Envelope.FunctionIdentifier(101, "getKey")
    static let signPSBT = Envelope.FunctionIdentifier(102, "signPSBT")
    static let getOutputDescriptor = Envelope.FunctionIdentifier(103, "getOutputDescriptor")
}

public extension Envelope.ParameterIdentifier {
    static let seedDigest = Envelope.ParameterIdentifier(200, "seedDigest")
    static let derivationPath = Envelope.ParameterIdentifier(201, "derivationPath")
    static let isPrivate = Envelope.ParameterIdentifier(202, "isPrivate")
    static let useInfo = Envelope.ParameterIdentifier(203, "useInfo")
    static let isDerivable = Envelope.ParameterIdentifier(204, "isDerivable")
    static let psbt = Envelope.ParameterIdentifier(205, "psbt")
    static let name = Envelope.ParameterIdentifier(206, "name")
    static let challenge = Envelope.ParameterIdentifier(207, "challenge")
}

public func addKnownFunctionExtensions() {
    let identifiers: [Envelope.FunctionIdentifier] = [
        .getSeed,
        .getKey,
        .signPSBT,
        .getOutputDescriptor,
    ]
    
    identifiers.forEach {
        Envelope.FunctionIdentifier.setKnownIdentifier($0)
    }

    let parameters: [Envelope.ParameterIdentifier] = [
        .seedDigest,
        .derivationPath,
        .isPrivate,
        .useInfo,
        .isDerivable,
        .psbt,
        .name,
        .challenge,
    ]
    
    parameters.forEach {
        Envelope.ParameterIdentifier.setKnownParameter($0)
    }
}
