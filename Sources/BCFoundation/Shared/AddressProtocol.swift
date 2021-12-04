//
//  AddressProtocol.swift
//  BCFoundation
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation

public protocol AddressProtocol: CustomStringConvertible, Equatable {
    var useInfo: UseInfo { get }
    var string: String { get }
}

public func ==<T: AddressProtocol>(lhs: T, rhs: T) -> Bool {
    lhs.string == rhs.string
}
