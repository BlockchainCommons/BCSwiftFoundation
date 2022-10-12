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
    public static var function: FunctionIdentifier = .signPSBT
    public let psbt: PSBT
    public let isRawPSBT: Bool
    
    public init(psbt: PSBT, isRawPSBT: Bool = false) {
        self.psbt = psbt
        self.isRawPSBT = isRawPSBT
    }
}

public extension PSBTSignatureRequestBody {
    var envelope: Envelope {
        try! Envelope(function: .signPSBT)
            .addAssertion(.parameter(.psbt, value: psbt))
    }
    
    init(_ envelope: Envelope) throws {
        self.init(psbt: try envelope.extractObject(PSBT.self, forParameter: .psbt))
    }
}
