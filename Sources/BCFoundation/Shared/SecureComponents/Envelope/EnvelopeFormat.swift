import Foundation
import WolfBase

protocol EnvelopeFormat {
    var formatItem: EnvelopeFormatItem { get }
}

extension Digest: EnvelopeFormat {
    var formatItem: EnvelopeFormatItem {
        return .item(data.prefix(8).hex)
    }
}

extension SCID: EnvelopeFormat {
    var formatItem: EnvelopeFormatItem {
        return .item(data.hex)
    }
}

extension CBOR: EnvelopeFormat {
    var formatItem: EnvelopeFormatItem {
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
            case CBOR.tagged(URType.envelope.tag, _):
                return try Envelope(taggedCBOR: cbor).formatItem
            case CBOR.tagged(.predicate, let cbor):
                guard
                    case let CBOR.unsignedInt(rawValue) = cbor,
                    case let predicate = Predicate(rawValue: rawValue)
                else {
                    return "<unknown predicate>"
                }
                return .item(predicate†)
            case CBOR.tagged(.signature, _):
                return "Signature"
            case CBOR.tagged(.nonce, _):
                return "Nonce"
            case CBOR.tagged(URType.sealedMessage.tag, _):
                return "SealedMessage"
            case CBOR.tagged(URType.sskrShare.tag, _):
                return "SSKRShare"
            case CBOR.tagged(URType.publicKeyBase.tag, _):
                return "PublicKeyBase"
            case CBOR.tagged(.uri, _):
                return try .item(URL(taggedCBOR: self)†.flanked("URI(", ")"))
            case CBOR.tagged(URType.digest.tag, _):
                return try .item(Digest(taggedCBOR: self)†)
            case CBOR.tagged(URType.scid.tag, _):
                return try .item(SCID(taggedCBOR: self)†)
            default:
                return "CBOR"
            }
        } catch {
            return "<error>"
        }
    }
}

extension Subject: EnvelopeFormat {
    var formatItem: EnvelopeFormatItem {
        switch self {
        case .leaf(let cbor, _):
            return cbor.formatItem
        case .envelope(let envelope):
            return envelope.formatItem
        case .encrypted(_, _):
            return "EncryptedMessage"
        case .redacted(_):
            return "REDACTED"
        }
    }
}

extension Assertion: EnvelopeFormat {
    var formatItem: EnvelopeFormatItem {
        .list([predicate.formatItem, ": ", object.formatItem])
    }
}

extension Envelope: EnvelopeFormat {
    public var format: String {
        formatItem.format.trim()
    }
    
    var formatItem: EnvelopeFormatItem {
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
        var items: [EnvelopeFormatItem] = []
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

public enum EnvelopeFormatItem {
    case begin(String)
    case end(String)
    case item(String)
    case separator
    case list([EnvelopeFormatItem])
}

extension EnvelopeFormatItem: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self = .item(value)
    }
}

extension EnvelopeFormatItem: CustomStringConvertible {
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

extension EnvelopeFormatItem {
    var flatten: [EnvelopeFormatItem] {
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

extension EnvelopeFormatItem: Equatable {
    public static func ==(lhs: EnvelopeFormatItem, rhs: EnvelopeFormatItem) -> Bool {
        if case let .begin(l) = lhs, case let .begin(r) = rhs, l == r { return true }
        if case let .end(l) = lhs, case let .end(r) = rhs, l == r { return true }
        if case let .item(l) = lhs, case let .item(r) = rhs, l == r { return true }
        if case .separator = lhs, case .separator = rhs { return true }
        if case let .list(l) = lhs, case let .list(r) = rhs, l == r { return true }
        return false
    }
}

extension EnvelopeFormatItem {
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

extension EnvelopeFormatItem: Comparable {
    public static func <(lhs: EnvelopeFormatItem, rhs: EnvelopeFormatItem) -> Bool {
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

extension Array: Comparable where Element == EnvelopeFormatItem {
    public static func < (lhs: Array<EnvelopeFormatItem>, rhs: Array<EnvelopeFormatItem>) -> Bool {
        lhs.lexicographicallyPrecedes(rhs)
    }
}
