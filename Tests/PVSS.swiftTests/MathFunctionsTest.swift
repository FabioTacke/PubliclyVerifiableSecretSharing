//
//  MathFunctionsTest.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 27.04.17.
//
//

import XCTest
import BigInt
import CryptoSwift
@testable import PVSS_swift

class MathFunctionsTest: XCTestCase {
  
  func testPrimeGenerator() {
    for _ in 0...10 {
      XCTAssert(BigUInt.randomPrime(length: 128).isPrime(), "Generated integer that is not prime.")
    }
  }
  
  func testModulusCalculation() {
    let modulus: BigUInt = 2341
    
    // Positive value, remainder != 0
    var testValue: BigInt = 7919
    XCTAssertEqual(testValue.mod(modulus: modulus), 896)
    
    // Negative value, remainder != 0
    testValue = BigInt(abs: 7919, negative: true)
    XCTAssertEqual(testValue.mod(modulus: modulus), 1445)
    
    // Positive value, remainder == 0
    testValue = 35115
    XCTAssertEqual(testValue.mod(modulus: modulus), 0)
    
    // Negative value, remainder == 0
    testValue = BigInt(abs: 35115, negative: true)
    XCTAssertEqual(testValue.mod(modulus: modulus), 0)
  }
  
  func testDLEQ() {
    let g1: BigUInt = 8443
    let h1: BigUInt = 531216
    let g2: BigUInt = 1299721
    let h2: BigUInt = 14767239

    let w: BigUInt = 81647
    let q: BigUInt = 15487469
    let alpha: BigUInt = 163027
    let length: Int = 64
    
    var dleq: DLEQ = DLEQ(g1: g1, h1: h1, g2: g2, h2: h2, length: length, q: q, alpha: alpha, w: w)
    
    let a1: BigUInt = 14735247
    let a2: BigUInt = 5290058
    
    XCTAssertEqual(a1, dleq.a1)
    XCTAssertEqual(a2, dleq.a2)
    
    let c: BigUInt = 127997
    dleq.c = c
    
    let r: BigUInt = 10221592
    
    XCTAssertEqual(r, dleq.r!)
    
    XCTAssertEqual(a1, (dleq.g1.power(dleq.r!, modulus: dleq.q) * h1.power(dleq.c!, modulus: dleq.q)) % q)
    XCTAssertEqual(a2, (dleq.g2.power(dleq.r!, modulus: dleq.q) * h2.power(dleq.c!, modulus: dleq.q)) % q)
  }
  
  func testPolynomial() {
    let q: BigUInt = 15486967
    let coefficients: [BigUInt] = [105211, 1548877	, 892134, 3490857, 324, 14234735]
    let x: BigUInt = 278
    
    let polynomial = Polynomial(coefficients: coefficients)

    XCTAssertEqual(polynomial.getValue(x: x) % q, 4115179)
  }
  
  func testHashing() {
    let value1: BigUInt = BigUInt("43589072349864890574839")!
    let value2: BigUInt = BigUInt("14735247304952934566")!
    
    var digest = SHA2(variant: .sha256)
    let _ = try! digest.update(withBytes: value1.description.data(using: .utf8)!)
    let _ = try! digest.update(withBytes: value2.description.data(using: .utf8)!)
    let result = try! digest.finish()
    
    XCTAssertEqual(result.toHexString(), "e25e5b7edf4ea66e5238393fb4f183e0fc1593c69a522f9255a51bd0bc2b7ba7")
    XCTAssertEqual(BigUInt(result.toHexString(), radix: 16), BigUInt(stringLiteral: "102389418883295205726805934198606438410316463205994911160958467170744727731111"))
  }
  
  func testXor() {
    let a = BigUInt(1337)
    let b = BigUInt(42)
    let xor = a ^ b
    
    XCTAssertEqual(xor, BigUInt(1299))
  }
  
  func testLagrange() {
    let lagrangeCoefficient = PVSSInstance.lagrangeCoefficient(i: 3, values: [1, 3, 4])
    
    XCTAssertEqual(lagrangeCoefficient.numerator, 4)
    XCTAssertEqual(lagrangeCoefficient.denominator, -2)
  }
}
