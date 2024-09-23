//
//  PSBTSigningStatus.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/10/21.
//

import Foundation

public struct PSBTSigningStatus<SignerType: PSBTSigner>: Identifiable, Sendable {
    public let id = UUID()
    public let origin: PSBTSigningOrigin
    public let isSigned: Bool
    public let knownSigner: SignerType?
    
    public enum Status {
        case isSignedBy(SignerType)
        case isSignedByUnknown
        case canBeSignedBy(SignerType)
        case noKnownSigner
    }
    
    public var status: Status {
        if isSigned {
            if let knownSigner = knownSigner {
                return .isSignedBy(knownSigner)
            } else {
                return .isSignedByUnknown
            }
        } else {
            if let knownSigner = knownSigner {
                return .canBeSignedBy(knownSigner)
            } else {
                return .noKnownSigner
            }
        }
    }
    
    public var canBeSigned: Bool {
        isSigned == false && knownSigner != nil
    }
}
