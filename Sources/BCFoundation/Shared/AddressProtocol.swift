//
//  AddressProtocol.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation

public protocol AddressProtocol: CustomStringConvertible {
    var useInfo: UseInfo { get }
    var string: String { get }
}
