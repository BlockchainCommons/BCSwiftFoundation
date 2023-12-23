import Envelope

extension Envelope {
    func addOptionalStringAssertionWithElisionLimit(_ predicate: KnownValue, _ string: String, limit: Int) -> (Envelope, Bool) {
        if string.isEmpty {
            return (self, false)
        } else if string.count <= limit {
            return (self.addAssertion(predicate, string), false)
        } else {
            return (self.addAssertion(predicate, Envelope(string).elide()), true)
        }
    }
}
