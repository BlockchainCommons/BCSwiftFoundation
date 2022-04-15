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
        return .item(uuidString)
    }
}

extension Reference: SimplexFormat {
    var formatItem: SimplexFormatItem {
        switch self {
        case .digest(let digest):
            return digest.formatItem
        case .scid(let scid, let digest):
            return .list([.item("("), scid.formatItem, .item(" "), digest.formatItem, .item(")")])
        }
    }
}

extension CBOR: SimplexFormat {
    var formatItem: SimplexFormatItem {
        switch self {
        case CBOR.tagged(URType.simplex.tag, _):
            return try! Simplex(taggedCBOR: cbor).formatItem
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
        case CBOR.tagged(URType.sealedMessage.tag, _):
            return .item("SealedMessage")
        case .utf8String(let string):
            return .item(string.flanked(.quote))
        default:
            return .item("CBOR")
        }
    }
}

extension Subject: SimplexFormat {
    var formatItem: SimplexFormatItem {
        switch self {
        case .plaintext(let cbor, _):
            return cbor.formatItem
        case .encrypted(_, _):
            return .item("<encrypted>")
        case .reference(let reference):
            return reference.formatItem
        }
    }
}

extension Assertion: SimplexFormat {
    var formatItem: SimplexFormatItem {
        switch self {
        case .declare(let predicate, let object, _):
            return .list([predicate.formatItem, .item(": "), object.formatItem])
        case .amend(let assertion, let object, _):
            return .list([.item(".amend("), assertion.formatItem, object.formatItem, .item(")")])
        case .revoke(let assertion, _):
            return .list([.item(".revoke("), assertion.formatItem, .item(")")])
        }
    }
}

extension Simplex: SimplexFormat {
    public var format: String {
        formatItem.format.trim()
    }
    
    var formatItem: SimplexFormatItem {
        if assertions.isEmpty {
            return subject.formatItem
        } else {
            let assertionsItems = assertions.map { [$0.formatItem] }
            let joinedAssertionsItems = Array(assertionsItems.joined(separator: [.separator]))
            return .list([
                .begin("{"),
                subject.formatItem,
                .item(" "),
                .list([
                    .begin("["),
                    .list(joinedAssertionsItems),
                    .end("]")
                ]),
                .end("}")
            ])
        }
    }
}

enum SimplexFormatItem {
    case begin(String)
    case end(String)
    case item(String)
    case separator
    case list([SimplexFormatItem])
    
    var flatten: [SimplexFormatItem] {
        if case let .list(items) = self {
            return items.map { $0.flatten }.flatMap { $0 }
        } else {
            return [self]
        }
    }
    
    func indent(_ level: Int) -> String {
        String(repeating: " ", count: level * 3)
    }
    
    var format: String {
        var lines: [String] = []
        var level = 0
        var currentLine = ""
        var items = flatten
        if case .begin(_) = items[0] {
            items = items.dropFirst().dropLast()
        }
        for item in items {
            switch item {
            case .begin(let string):
                lines.append(indent(level) + currentLine + string + .newline)
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
                lines.append(indent(level) + currentLine + .newline)
                currentLine = ""
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
