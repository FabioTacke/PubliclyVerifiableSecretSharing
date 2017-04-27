import XCTest
@testable import PVSS_swift

class PVSS_swiftTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(PVSS_swift().text, "Hello, World!")
    }


    static var allTests = [
        ("testExample", testExample),
    ]
}
