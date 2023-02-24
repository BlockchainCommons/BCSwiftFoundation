import Foundation
import Envelope

public extension Function {
    static let getSeed = Function(100, "getSeed")
    static let getKey = Function(101, "getKey")
    static let signPSBT = Function(102, "signPSBT")
    static let getOutputDescriptor = Function(103, "getOutputDescriptor")
}

public extension Parameter {
    static let seedDigest = Parameter(200, "seedDigest")
    static let derivationPath = Parameter(201, "derivationPath")
    static let isPrivate = Parameter(202, "isPrivate")
    static let useInfo = Parameter(203, "useInfo")
    static let isDerivable = Parameter(204, "isDerivable")
    static let psbt = Parameter(205, "psbt")
    static let name = Parameter(206, "name")
    static let challenge = Parameter(207, "challenge")
}

public func addKnownFunctionExtensions() {
    let identifiers: [Function] = [
        .getSeed,
        .getKey,
        .signPSBT,
        .getOutputDescriptor,
    ]
    
    identifiers.forEach {
        knownFunctions.insert($0)
    }

    let parameters: [Parameter] = [
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
        knownParameters.insert($0)
    }
}
