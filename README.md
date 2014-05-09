CryptoSMT
=========

CryptoSMT is an easy to use tool for cryptanalysis of symmetric primitives likes block ciphers or hash functions. It is based on SMT/SAT solvers like STP and CryptoMiniSat and provides a simple framework to use them for cryptanalytic techniques.

This can be for instance used to proof the resistance of a block cipher against differential cryptanalysis or to discover weaknesses against these techniques.

At the moment CryptoSMT supports the following primitives:

* Simon [2]
* Speck [2]

For information on how to install CryptoSMT and a tutorial on how to use it see the [project website](http://kste.github.io/cryptosmt/).

References
----------

[1] [Towards Finding Optimal Differential Characteristics for ARX: Application to Salsa20](http://eprint.iacr.org/2013/328)

[2] [The SIMON and SPECK Families of Lightweight Block Ciphers](http://eprint.iacr.org/2013/404)

