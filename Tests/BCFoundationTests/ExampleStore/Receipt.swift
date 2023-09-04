import Foundation
import BCFoundation

public struct Receipt: Hashable {
    let data: Data
    
    init(_ data: Data) {
        self.data = data
    }
    
    init(userID: ARID, payload: Data) {
        self.data = Digest(userID.data + payload).data
    }
}

extension Receipt: CustomStringConvertible {
    public var description: String {
        "Receipt(\(data.hex))"
    }
}

extension Receipt: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(data)
            .addType("receipt")
    }
    
    public init(_ envelope: Envelope) throws {
        try envelope.checkType("receipt")
        self.init(try envelope.extractSubject(Data.self))
    }
}
