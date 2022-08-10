import Foundation

public extension FunctionIdentifier {
    static let getSeed = FunctionIdentifier(100, "getSeed")
    static let getKey = FunctionIdentifier(101, "getKey")
    static let signPSBT = FunctionIdentifier(102, "signPSBT")
    static let getOutputDescriptor = FunctionIdentifier(103, "getOutputDescriptor")
}

public extension FunctionParameter {
    static let seedDigest = FunctionParameter(200, "seedDigest")
    static let derivationPath = FunctionParameter(201, "derivationPath")
    static let isPrivate = FunctionParameter(202, "isPrivate")
    static let useInfo = FunctionParameter(203, "useInfo")
    static let isDerivable = FunctionParameter(204, "isDerivable")
    static let psbt = FunctionParameter(205, "psbt")
    static let name = FunctionParameter(206, "name")
    static let challenge = FunctionParameter(207, "challenge")
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

    let parameters: [FunctionParameter] = [
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
        FunctionParameter.setKnownParameter($0)
    }
}
