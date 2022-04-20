import Foundation
import WolfBase

protocol SimplexFormat {
    var formatItem: SimplexFormatItem { get }
}

extension Digest: SimplexFormat {
    var formatItem: SimplexFormatItem {
        return .item(rawValue.prefix(8).hex)
    }
}

extension SCID: SimplexFormat {
    var formatItem: SimplexFormatItem {
        return .item(rawValue.hex)
    }
}

extension CBOR: SimplexFormat {
    var formatItem: SimplexFormatItem {
        do {
            switch self {
            case .unsignedInt(let n):
                return .item(String(n))
            case .utf8String(let string):
                return .item(string.flanked(.quote))
            case .date(let date):
                var s = date.ISO8601Format()
                if s.count == 20 && s.hasSuffix("T00:00:00Z") {
                    s = s.prefix(count: 10)
                }
                return .item(s)
            case CBOR.tagged(URType.simplex.tag, _):
                return try Simplex(taggedCBOR: cbor).formatItem
            case CBOR.tagged(.predicate, let cbor):
                guard
                    case let CBOR.unsignedInt(rawValue) = cbor,
                    case let predicate = Predicate(rawValue: rawValue)
                else {
                    return .item("<unknown predicate>")
                }
                return .item(predicate†)
            case CBOR.tagged(.signature, _):
                return .item("Signature")
            case CBOR.tagged(.nonce, _):
                return .item("Nonce")
            case CBOR.tagged(URType.sealedMessage.tag, _):
                return .item("SealedMessage")
            case CBOR.tagged(URType.sskrShare.tag, _):
                return .item("SSKRShare")
            case CBOR.tagged(URType.pubkeys.tag, _):
                return .item("PublicKeyBase")
            case CBOR.tagged(.uri, _):
                return try .item(URL(taggedCBOR: self)†.flanked("URI(", ")"))
            case CBOR.tagged(URType.digest.tag, _):
                return try .item(Digest(taggedCBOR: self)†)
            case CBOR.tagged(URType.scid.tag, _):
                return try .item(SCID(taggedCBOR: self)†)
            default:
                return .item("CBOR")
            }
        } catch {
            return .item("<error>")
        }
    }
}

extension Subject: SimplexFormat {
    var formatItem: SimplexFormatItem {
        switch self {
        case .plaintext(let cbor, _):
            return cbor.formatItem
        case .encrypted(_, _):
            return .item("EncryptedMessage")
        }
    }
}

extension Assertion: SimplexFormat {
    var formatItem: SimplexFormatItem {
        switch self {
        case .declare(let predicate, let object, _):
            return .list([predicate.formatItem, .item(": "), object.formatItem])
        }
    }
}

extension Simplex: SimplexFormat {
    public var format: String {
        formatItem.format.trim()
    }
    
    var formatItem: SimplexFormatItem {
        let subjectItem = subject.formatItem
        let isList: Bool
        if case .list(_) = subjectItem {
            isList = true
        } else {
            isList = false
        }

        let assertionsItems = assertions.map { [$0.formatItem] }.sorted()
        let joinedAssertionsItems = Array(assertionsItems.joined(separator: [.separator]))
        let hasAssertions = !joinedAssertionsItems.isEmpty
        var items: [SimplexFormatItem] = []
        if isList {
            items.append(.begin("{"))
        }
        items.append(subjectItem)
        if isList {
            if hasAssertions {
                items.append(.end("} ["))
                items.append(.begin(""))
            } else {
                items.append(.end("}"))
            }
        }
        if hasAssertions {
            if !isList {
                items.append(.begin("["))
            }
            items.append(.list(joinedAssertionsItems))
            items.append(.end("]"))
        }
        return .list(items)
    }
}

public enum SimplexFormatItem {
    case begin(String)
    case end(String)
    case item(String)
    case separator
    case list([SimplexFormatItem])
}

extension SimplexFormatItem: CustomStringConvertible {
    public var description: String {
        switch self {
        case .begin(let string):
            return ".begin(\(string))"
        case .end(let string):
            return ".end(\(string))"
        case .item(let string):
            return ".item(\(string))"
        case .separator:
            return ".separator"
        case .list(let array):
            return ".array(\(array))"
        }
    }
}

extension SimplexFormatItem {
    var flatten: [SimplexFormatItem] {
        if case let .list(items) = self {
            return items.map { $0.flatten }.flatMap { $0 }
        } else {
            return [self]
        }
    }
    
    func indent(_ level: Int) -> String {
        String(repeating: " ", count: level * 4)
    }
    
    private func addSpaceAtEndIfNeeded(_ s: String) -> String {
        guard !s.isEmpty else {
            return " "
        }
        if s.last! == " " {
            return s
        } else {
            return s + " "
        }
    }
    
    var format: String {
        var lines: [String] = []
        var level = 0
        var currentLine = ""
        let items = flatten
        for item in items {
            switch item {
            case .begin(let string):
                if !string.isEmpty {
                    let c = currentLine.isEmpty ? string : addSpaceAtEndIfNeeded(currentLine) + string
                    lines.append(indent(level) + c + .newline)
                }
                level += 1
                currentLine = ""
            case .end(let string):
                if !currentLine.isEmpty {
                    lines.append(indent(level) + currentLine + .newline)
                    currentLine = ""
                }
                level -= 1
                lines.append(indent(level) + string + .newline)
            case .item(let string):
                currentLine += string
            case .separator:
                if !currentLine.isEmpty {
                    lines.append(indent(level) + currentLine + .newline)
                    currentLine = ""
                }
            case .list:
                lines.append("<list>")
            }
        }
        if !currentLine.isEmpty {
            lines.append(currentLine)
        }
        return lines.joined()
    }
}

extension SimplexFormatItem: Equatable {
    public static func ==(lhs: SimplexFormatItem, rhs: SimplexFormatItem) -> Bool {
        if case let .begin(l) = lhs, case let .begin(r) = rhs, l == r { return true }
        if case let .end(l) = lhs, case let .end(r) = rhs, l == r { return true }
        if case let .item(l) = lhs, case let .item(r) = rhs, l == r { return true }
        if case .separator = lhs, case .separator = rhs { return true }
        if case let .list(l) = lhs, case let .list(r) = rhs, l == r { return true }
        return false
    }
}

extension SimplexFormatItem {
    var index: Int {
        switch self {
        case .begin:
            return 1
        case .end:
            return 2
        case .item:
            return 3
        case .separator:
            return 4
        case .list:
            return 5
        }
    }
}

extension SimplexFormatItem: Comparable {
    public static func <(lhs: SimplexFormatItem, rhs: SimplexFormatItem) -> Bool {
        let lIndex = lhs.index
        let rIndex = rhs.index
        if lIndex < rIndex {
            return true
        } else if rIndex < lIndex {
            return false
        }
        if case let .begin(l) = lhs, case let .begin(r) = rhs, l < r { return true }
        if case let .end(l) = lhs, case let .end(r) = rhs, l < r { return true }
        if case let .item(l) = lhs, case let .item(r) = rhs, l < r { return true }
        if case .separator = lhs, case .separator = rhs { return false }
        if case let .list(l) = lhs, case let .list(r) = rhs, l.lexicographicallyPrecedes(r) { return true }
        return false
    }
}

extension Array: Comparable where Element == SimplexFormatItem {
    public static func < (lhs: Array<SimplexFormatItem>, rhs: Array<SimplexFormatItem>) -> Bool {
        lhs.lexicographicallyPrecedes(rhs)
    }
}
