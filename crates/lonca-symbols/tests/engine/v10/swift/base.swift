import Foundation

/// A client.
public class Client {
    let id: Int = 0
    var total = 0

    init(total: Int) {
        self.total = total
    }

    deinit {
        stop()
    }

    func charge(amount: Int) -> Int {
        return total + amount
    }

    func charge(amount: Int64, why: String) -> Int {
        return total
    }

    func testCharge() {
        assert(true)
    }

    @Test func marked() {
        assert(true)
    }
}

extension Client {
    func more() -> Int {
        return 1
    }
}

extension Client: Equatable {
    func eq() -> Bool {
        return true
    }
}

struct Point {
    var x: Int

    func sum() -> Int {
        return x
    }
}

protocol Shape {
    func area() -> Double
    var name: String { get }
}

typealias Name = String

func top(x: Int) -> Int {
    return x
}
