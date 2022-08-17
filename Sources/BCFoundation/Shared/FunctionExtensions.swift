import Foundation

public extension FunctionIdentifier {
    static let getSeed = FunctionIdentifier(100, "getSeed")
    static let getKey = FunctionIdentifier(101, "getKey")
    static let signPSBT = FunctionIdentifier(102, "signPSBT")
    static let getOutputDescriptor = FunctionIdentifier(103, "getOutputDescriptor")
}

public extension ParameterIdentifier {
    static let seedDigest = ParameterIdentifier(200, "seedDigest")
    static let derivationPath = ParameterIdentifier(201, "derivationPath")
    static let isPrivate = ParameterIdentifier(202, "isPrivate")
    static let useInfo = ParameterIdentifier(203, "useInfo")
    static let isDerivable = ParameterIdentifier(204, "isDerivable")
    static let psbt = ParameterIdentifier(205, "psbt")
    static let name = ParameterIdentifier(206, "name")
    static let challenge = ParameterIdentifier(207, "challenge")
}

public func addKnownFunctionExtensions() {
    let identifiers: [FunctionIdentifier] = [
        .getSeed,
        .getKey,
        .signPSBT,
        .getOutputDescriptor,
    ]
    
    identifiers.forEach {
        FunctionIdentifier.setKnownIdentifier($0)
    }

    let parameters: [ParameterIdentifier] = [
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
        ParameterIdentifier.setKnownParameter($0)
    }
}
