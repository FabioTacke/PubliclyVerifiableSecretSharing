//
//  Polynomial.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt
import Bignum

public struct Polynomial {
  let coefficients: [Bignum]
  
  public init(coefficients: [Bignum]) {
    self.coefficients = coefficients
  }
  
  public init(degree: Int, bitLength: Int, q: Bignum) {
    var coefficientList: [Bignum] = []
    
    for _ in 0...degree {
      let threshold = BigUInt(q.description)!
        coefficientList.append(Bignum(BigUInt.randomInteger(lessThan: threshold).description))
    }
    
   self.init(coefficients: coefficientList)
  }
  
  // Calculate p(x)
  public func getValue(x: Bignum) -> Bignum {
    var result = coefficients[0]
    var temp: Bignum = 1
    
    for i in 1..<coefficients.count {
      temp = (temp * x)
      result = (result + (coefficients[i] * temp))
    }
    
    return result
  }
}
