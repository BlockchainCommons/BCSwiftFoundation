//
//  IdentityDigestable.swift
//  
//
//  Created by Wolf McNally on 12/1/21.
//

import Foundation
import CryptoSwift

public protocol IdentityDigestable {
    var identityDigestSource: Data { get }
    var identityDigest: Data { get }
}

extension IdentityDigestable {
    public var identityDigest: Data {
        identityDigestSource.sha256()
    }
}

extension Data: IdentityDigestable {
    public var identityDigestSource: Data {
        self
    }
}

extension String: IdentityDigestable {
    public var identityDigestSource: Data {
        self.data(using: .utf8)!
    }
}
