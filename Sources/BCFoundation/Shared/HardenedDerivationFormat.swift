import Foundation

public enum HardenedDerivationFormat {
    case tickMark
    case letter
    
    public var string: String {
        switch self {
        case .tickMark:
            return "'"
        case .letter:
            return "h"
        }
    }
}
