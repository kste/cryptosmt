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

The following primitives are supported by CryptoSMT at the moment: Simon, Speck, Keccak,
Ketje, Chaskey, SipHash, Salsa, ChaCha, Ascon

Please note that at the moment not all features are available for all ciphers. A
detailed description on the application of this tool on the SIMON block ciphers and
how a differential/linear model for SIMON can be constructed is given in [1].

For information on how to install CryptoSMT and a tutorial on how to use it see 
the [project website](http://www2.compute.dtu.dk/~stek/cryptosmt.html).

References
----------

[1] [Observations on the SIMON block cipher family](http://eprint.iacr.org/2015/145)

BibTex
----------
```
@misc{CryptoSMT-ref,
    author = {{Stefan Kölbl}},
    title = {{CryptoSMT: An easy to use tool for cryptanalysis of symmetric primitives}},
    note = {\url{https://github.com/kste/cryptosmt}},
}
```
