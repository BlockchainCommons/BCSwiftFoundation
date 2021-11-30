//
//  KeyType.swift
//  BCFoundation
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation

@frozen
public enum KeyType: Identifiable, CaseIterable {
    case `private`
    case `public`
    
    public var id: String {
        switch self {
        case .private:
            return "keytype-private"
        case .public:
            return "keytype-public"
        }
    }

    public var name: String {
        switch self {
        case .private:
            return "Private"
        case .public:
            return "Public"
        }
    }
    
    public var isPrivate: Bool {
        switch self {
        case .private:
            return true
        case .public:
            return false
        }
    }
    
    public init(isPrivate: Bool) {
        if isPrivate {
            self = .private
        } else {
            self = .public
        }
    }
}
