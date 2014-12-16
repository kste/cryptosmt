CryptoSMT
=========

CryptoSMT is an easy to use tool for cryptanalysis of symmetric primitives likes 
block ciphers or hash functions. It is based on SMT/SAT solvers like STP, Boolector, 
CryptoMiniSat and provides a simple framework to use them for cryptanalytic techniques.

Some of the features are:
* Proof properties regarding the differential behavious of a primitive.
* Find the best linear/differential characteristics.
* Compute probability of a differential.
* Find preimages for hash functions.
* Recover a secret key.

The following primitives are supported by CryptoSMT at the moment:

* Simon [2]
* Speck [2]
* Keccak [3]
* SipHash [4]
* ChasKey [5]

Please note that at the moment not all features are available for all ciphers.

For information on how to install CryptoSMT and a tutorial on how to use it see 
the [project website](http://kste.github.io/cryptosmt/).

References
----------

[1] [Towards Finding Optimal Differential Characteristics for ARX: Application to Salsa20](http://eprint.iacr.org/2013/328)

[2] [The SIMON and SPECK Families of Lightweight Block Ciphers](http://eprint.iacr.org/2013/404)

[3] [The Keccak Reference](http://keccak.noekeon.org/Keccak-reference-3.0.pdf)

[4] [SipHash: a fast short-input PRF](https://131002.net/siphash/)

[5] [Chaskey: An Efficient MAC Algorithm for 32-bit Microcontroller](http://eprint.iacr.org/2014/386)

