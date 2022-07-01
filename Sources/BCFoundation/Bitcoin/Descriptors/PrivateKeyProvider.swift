//
//  PrivateKeyProvider.swift
//  
//
//  Created by Wolf McNally on 12/4/21.
//

import Foundation

public typealias PrivateKeyProvider = (HDKeyProtocol) throws -> HDKey?
