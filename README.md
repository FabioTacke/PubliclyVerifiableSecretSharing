# PVSS - Publicly Verifiable Secret Sharing

The library implements a PVSS scheme in Swift. The algorithm is based on "A Simple Publicly Verifiable Secret Sharing Scheme and its Application to Electronic Voting" by Berry Schoenmakers.

## What is PVSS?
Secret sharing means a dealer can split a secret among a group of participants which can reconstruct the secret only by collaboratively joining their parts of the secret. The library also implements threshold cryptography so that the dealer can decide whether all of the receiving participants need to collaborate or if a smaller subgroup of participants is sufficient to reconstruct the secret.

In addition to the plain secret sharing scheme PVSS adds verifiability in the following way: All the parts the secret is split into are encrypted with the receivers' public keys respectively. The dealer publishes all the encrypted shares along with a non-interactive zero-knowledge proof that allows everbody (not only the receiving participants) to verify that the decrypted shares indeed can be used to reconstruct the secret. The participants then decrypt all their shares and exchange them along with another non-interactive zero-knowledge proof that allows the receiving participant to verify that the share is actually the result of the decryption.

Thus PVSS can be used to share a secret among a group of participants so that either the secret can be reconstructed by the participants who all play fair or a participant that received a faked share can identify the malicious party.

## Installation

### Swift Package Manager
`.Package(url: "https://github.com/FabioTacke/PubliclyVerifiableSecretSharing.git", majorVersion: 2)`

### CocoaPods (version 2 not supported yet)
`pod 'PVSS', '~> 1.0'`

## Build settings
Since version 2.0.0 PVSS uses GMP for speeding up the calculations. If you don't have GMP installed there's a compiled GMP library version 6.1.2 included. However you need to provide the compiler and the linker with the information where to find the GMP header file and the library. Example:

`swift [build | test] -Xcc -Igmp/include -Xlinker -Lgmp/lib`

You can replace those paths if you already have GMP installed.

## Usage
This section will guide you through the basic steps taken in the PVSS scheme.

### Setup
At first we convert our secret message into a numeric value if necessary. When creating the dealer a PVSS instance is created as well which holds all the global parameters that every participant needs to know.

```swift
import PVSS
import BigInt
import Bignum

let secretMessage = "Correct horse battery staple."
let secret = Bignum(data: secretMessage.data(using: .utf8)!)

// Create PVSS Instance.
let dealer = Participant()

// Participants p1, p2 and p3.
let p1 = Participant(pvssInstance: dealer.pvssInstance)
let p2 = Participant(pvssInstance: dealer.pvssInstance)
let p3 = Participant(pvssInstance: dealer.pvssInstance)
```
### Distribution & Verification
The dealer splits the secret into shares, encrypts them and creates a proof so that everybody can verify that the shares (once decrypted) can be used to reconstruct the secret. The threshold determines how many shares are necessary for the reconstruction. The encrypted shares and the proof are then bundled together.

```swift
// Dealer that shares the secret among p1, p2 and p3.
let distributionBundle = dealer.distribute(secret: secret, publicKeys: [p1.publicKey, p2.publicKey, p3.publicKey], threshold: 3)

// p1 verifies distribution bundle containing encryted shares and proof. [p2 and p3 do this as well.]
assert(p1.pvssInstance.verify(distributionBundle: distributionBundle))
```

### Exchange & Verification
The participants extract their shares from the distribution bundle and decrypt them. They bundle them together with a proof that allows the receiver to verify that the share is indeed the result of the decryption.

```swift
// p1 extracts the share. [p2 and p3 do this as well.]
let s1 = p1.extractShare(distributionBundle: distributionBundle, privateKey: p1.privateKey)!

// p1, p2 and p3 exchange their shares.
// ...

// p1 verifies the share received from p2. [Actually everybody verifies every received share.]
assert(p1.pvssInstance.verify(shareBundle: s2, encryptedShare: distributionBundle.shares[p2.publicKey]!))
```

### Reconstruction
Once a participant collected at least `threshold` shares the secret can be reconstructed.

```swift
// p1 [as well as p2 and p3] can now reconstruct the secret.
let shareBundles = [s1, s2, s3]
let r1 = p1.pvssInstance.reconstruct(shareBundles: shareBundles, distributionBundle: distributionBundle)!

String(data: BigUInt(r1.description)!.serialize(), encoding: .utf8)!
// Correct horse battery staple.
```

## Licenses
PVSS makes use of the following third party libraries.

BigInt - Copyright (c) 2016-2017 Károly Lőrentey (MIT)

CryptoSwift - Copyright (c) 2014-2017 Marcin Krzyżanowski (zlib)

GMP - Copyright (c) 2007-2017 Free Software Foundation, Inc. (GNU LGPL)
