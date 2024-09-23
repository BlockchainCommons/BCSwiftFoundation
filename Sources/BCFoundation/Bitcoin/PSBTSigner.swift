//
//  PSBTSigner.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/10/21.
//

import Foundation

public protocol PSBTSigner : Hashable, Sendable {
    var masterKey: HDKey { get }
}
