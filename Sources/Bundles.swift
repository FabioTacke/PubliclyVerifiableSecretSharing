//
//  Bundles.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt
import Bignum

public struct ShareBundle {
  public let publicKey: Bignum
  public let share: Bignum
  public let challenge: Bignum
  public let response: Bignum
  
  public init(publicKey: Bignum, share: Bignum, challenge: Bignum, response: Bignum)
  {
    self.publicKey = publicKey
    self.share = share
    self.challenge = challenge
    self.response = response
  }
}

public struct DistributionBundle {
  public let commitments: [Bignum]
  public let positions: [Bignum: Int]
  public let shares: [Bignum: Bignum]
  public let publicKeys: [Bignum]
  public let challenge: Bignum
  public let responses: [Bignum: Bignum]
  public let U: Bignum
  
  public init(commitments: [Bignum], positions: [Bignum: Int], shares: [Bignum: Bignum], publicKeys: [Bignum], challenge: Bignum, responses: [Bignum: Bignum], U: Bignum) {
    self.commitments = commitments
    self.positions = positions
    self.shares = shares
    self.publicKeys = publicKeys
    self.challenge = challenge
    self.responses = responses
    self.U = U
  }
}
