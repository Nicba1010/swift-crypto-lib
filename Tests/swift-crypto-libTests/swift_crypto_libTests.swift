import XCTest
@testable import swift_crypto_lib

final class swift_crypto_libTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(swift_crypto_lib().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}