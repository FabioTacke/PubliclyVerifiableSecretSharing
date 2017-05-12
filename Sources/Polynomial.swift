//
//  Polynomial.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt

public struct Polynomial {
  let coefficients: [BigUInt]
  
  public init(coefficients: [BigUInt]) {
    self.coefficients = coefficients
  }
  
  public init(degree: Int, bitLength: Int, q: BigUInt) {
    var coefficientList: [BigUInt] = []
    
    for _ in 0...degree {
      coefficientList.append(BigUInt.randomInteger(withMaximumWidth: bitLength) % q)
    }
    
   self.init(coefficients: coefficientList)
  }
  
  // Calculate p(x)
  public func getValue(x: BigUInt) -> BigUInt {
    var result: BigUInt = coefficients[0]
    var temp: BigUInt = 1
    
    for i in 1..<coefficients.count {
      temp = (temp * x)
      result = (result + (coefficients[i] * temp))
    }
    
    return result
  }
}
