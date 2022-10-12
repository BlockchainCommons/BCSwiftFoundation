import Foundation

public struct GeneralError: LocalizedError {
    public let errorDescription: String?

    public init(_ errorDescription: String) {
        self.errorDescription = errorDescription
    }
}
