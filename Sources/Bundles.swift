//
//  Bundles.swift
//  PVSS
//
//  Created by Fabio Tacke on 30.04.17.
//
//

import Foundation
import BigInt

public struct ShareBundle {
  public let publicKey: BigUInt
  public let share: BigUInt
  public let challenge: BigUInt
  public let response: BigUInt
  
  public init(publicKey: BigUInt, share: BigUInt, challenge: BigUInt, response: BigUInt)
  {
    self.publicKey = publicKey
    self.share = share
    self.challenge = challenge
    self.response = response
  }
}

public struct DistributionBundle {
  public let commitments: [BigUInt]
  public let positions: [BigUInt: Int]
  public let shares: [BigUInt: BigUInt]
  public let publicKeys: [BigUInt]
  public let challenge: BigUInt
  public let responses: [BigUInt: BigUInt]
  public let U: BigUInt
  
  public init(commitments: [BigUInt], positions: [BigUInt: Int], shares: [BigUInt: BigUInt], publicKeys: [BigUInt], challenge: BigUInt, responses: [BigUInt: BigUInt], U: BigUInt) {
    self.commitments = commitments
    self.positions = positions
    self.shares = shares
    self.publicKeys = publicKeys
    self.challenge = challenge
    self.responses = responses
    self.U = U
  }
  
}
