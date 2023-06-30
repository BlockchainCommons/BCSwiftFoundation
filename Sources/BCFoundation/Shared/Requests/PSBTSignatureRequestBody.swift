//
//  PSBTSignatureRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit
import WolfBase

public struct PSBTSignatureRequestBody: TransactionRequestBody {
    public static var function = Function.signPSBT
    public let psbt: PSBT
    public let isRawPSBT: Bool
    
    public init(psbt: PSBT, isRawPSBT: Bool = false) {
        self.psbt = psbt
        self.isRawPSBT = isRawPSBT
    }
}

extension PSBTSignatureRequestBody: EnvelopeCodable {
    public var envelope: Envelope {
        try! Envelope(function: Self.function)
            .addAssertion(.parameter(.psbt, value: psbt))
    }
    
    public init(_ envelope: Envelope) throws {
        try envelope.checkFunction(Self.function)
        
        self.init(psbt: try envelope.extractObject(PSBT.self, forParameter: .psbt))
    }
}
