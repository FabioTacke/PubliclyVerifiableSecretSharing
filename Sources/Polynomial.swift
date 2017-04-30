//
//  Polynomial.swift
//  PVSS.swift
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt

public struct Polynomial {
  let coefficients: [BigUInt]
  let q: BigUInt
  
  init(coefficients: [BigUInt], q: BigUInt) {
    self.coefficients = coefficients
    self.q = q
  }
  
  init(degree: Int, q: BigUInt, bitLength: Int) {
    var coefficientList: [BigUInt] = []
    
    for _ in 0...degree {
      coefficientList.append(BigUInt.randomInteger(withMaximumWidth: bitLength))
    }
    
   self.init(coefficients: coefficientList, q: q)
  }
  
  // Calculate p(x)
  func getValue(x: BigUInt) -> BigUInt {
    var result: BigUInt = coefficients[0]
    var temp: BigUInt = 1
    
    for i in 1..<coefficients.count {
      temp = (temp * x) % q
      result = (result + (coefficients[i] * temp)) % q
    }
    
    return result
  }
}
