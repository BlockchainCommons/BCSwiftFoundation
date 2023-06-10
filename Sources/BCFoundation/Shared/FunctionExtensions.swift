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
    let fns: [Function] = [
        .getSeed,
        .getKey,
        .signPSBT,
        .getOutputDescriptor,
    ]
    
    fns.forEach {
        globalFunctions.insert($0)
    }

    let params: [Parameter] = [
        .seedDigest,
        .derivationPath,
        .isPrivate,
        .useInfo,
        .isDerivable,
        .psbt,
        .name,
        .challenge,
    ]
    
    params.forEach {
        globalParameters.insert($0)
    }
}
