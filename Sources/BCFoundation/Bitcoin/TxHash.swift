//
//  TxHash.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/9/21.
//

import Foundation
import BCWally

public struct TxHash: Equatable {
    public let data: Data
    
    public init?(_ data: Data) {
        guard data.count == SHA256_LEN else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(Data(data.reversed()))
    }
    
    public var hex: String {
        return data.reversed().hex
    }
}
