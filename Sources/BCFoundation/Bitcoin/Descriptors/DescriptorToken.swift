//
//  DescriptorToken.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
import Flexer

struct DescriptorToken: TokenProtocol {
    typealias Index = String.Index

    public enum Kind: Hashable {
        case openParen
        case closeParen
        case openBrace
        case closeBrace
        case openBracket
        case closeBracket
        case comma
        case slash
        case star
        
        case sh
        case wsh
        case pk
        case pkh
        case wpkh
        case combo
        case multi
        case sortedmulti
        case tr
        case addr
        case raw
        case cosigner
        
        case address
        case hdKey
        case wif
        case data
        case int
        case isHardened
        
        case checksum
    }

    var range: Range<Index>
    var kind: Kind
    var payload: Any?

    init(kind: Kind, range: Range<Index>) {
        self.kind = kind
        self.range = range
    }

    init(kind: Kind, range: Range<Index>, payload: Any) {
        self.kind = kind
        self.range = range
        self.payload = payload
    }

    static func == (lhs: DescriptorToken, rhs: DescriptorToken) -> Bool {
        lhs.kind == rhs.kind && lhs.range == rhs.range
    }
    
    var address: Bitcoin.Address {
        payload as! Bitcoin.Address
    }
    
    var data: Data {
        payload as! Data
    }
    
    var int: Int {
        payload as! Int
    }
    
    var hdKey: HDKey {
        payload as! HDKey
    }
    
    var wif: WIF {
        payload as! WIF
    }
}
