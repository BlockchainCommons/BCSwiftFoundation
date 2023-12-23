//
//  PSBTSignatureRequestBody.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import URKit
import WolfBase

public enum PSBTRequestStyle: Int {
    // From most- to least-preferred
    case envelope       // envelope:...
    case urVersion2     // ur:psbt/...
    case urVersion1     // ur:crypto-psbt/...
    case base64
}

public struct PSBTSignatureRequestBody: TransactionRequestBody {
    public static var function = Function.signPSBT
    public let psbt: PSBT
    public let psbtRequestStyle: PSBTRequestStyle
    
    public init(psbt: PSBT, psbtRequestStyle: PSBTRequestStyle = .envelope) {
        self.psbt = psbt
        self.psbtRequestStyle = psbtRequestStyle
    }
}

extension PSBTSignatureRequestBody: EnvelopeCodable {
    public var envelope: Envelope {
        let e1 = try! Envelope(function: Self.function)
            .addAssertion(.parameter(.psbt, value: psbt))
        
        let e2 = e1.addAssertion(if: psbtRequestStyle != .envelope, "_style", psbtRequestStyle.rawValue)
        
        return e2
    }
    
    public init(envelope: Envelope) throws {
        try envelope.checkFunction(Self.function)
        
        let object = try envelope.object(forParameter: .psbt)
        let psbt = try PSBT(envelope: object)
        let styleValue = (try? envelope.extractObject(Int.self, forPredicate: "_style")) ?? PSBTRequestStyle.envelope.rawValue
        let style = PSBTRequestStyle(rawValue: styleValue)!
        self.init(psbt: psbt, psbtRequestStyle: style)
    }
}
