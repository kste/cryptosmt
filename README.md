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
how a differential/linear model for SIMON can be constructed is given in [1]. This tool 
has also been used in [2], for finding the best differential trial and computing the more accurate differential
probability of the best differential for several block ciphers.

For information on how to install CryptoSMT and a tutorial on how to use it see 
the [project website](https://kste.dk/cryptosmt.html).

## Adding a cipher to the CryptoSMT's cipher suites
Let's say you want to add "NewCipher" to the tool:
1. Make a copy from an example in "./ciphers/" which is similar to the design you want to analyze (for example if you want an
ARX, Speck might be a good start) and rename it to "NewCipher.py".
2. Modify the content of "NewCipher.py" to adapt it to your cipher (here it's best to look at some examples, as it depends a lot on design).
3. Update the file "cryptosmt.py": Add "NewCipher" in the import (line 8), and include it in the tool by adding it to the ciphersuite (line 25).
4. Run "python3 cryptosmt.py --cipher NewCipher" to see if it works.
## How it works?
We can describe the process of the CryptoSMT as the following steps:
1. It creates an stp file which contains the SMT model of the differential cryptanaysis of the given cipher in CVC format (this file is placed in "./tmp/" folder)
2. After generation of SMT model in CVC format, it calls an SMT solver to solve the generated model. The STP is used by default as SMT solver. You can also use the Boolector as SMT solver. 
3. The SMT model contains some inherent constraints which are used for modeling the differential propagation rules, and some additional constrints which are used to model the outside counditions like the fixed input/output differentials values. 
4. One of the additional constraints is the starting weight (of the differential probability) constraint. The first SMT model is generated with the starting weight, and this model is changed repeatedly by increasing the weight by one, and each time, it's satisfiablity is checked by an SMT solver. The goal is to find the minimum weight which makes the model satisfiable. 
5. If the SMT model is satisfiable for the first time, the weight (of the differential probability) which is used, is reteurned as the minimum weight (of the differential probability) as one of the output, and the process is stoped.

These processes are almost realted to the mod0, which is used to find the best differential with maximum (minimum) differential probablity (weight).

References
----------

[1] [Observations on the SIMON block cipher family (2015)](http://eprint.iacr.org/2015/145)

[2] [Mind the Gap - A Closer Look at the Security of Block Ciphers against Differential Cryptanalysis (2018)](https://eprint.iacr.org/2018/689)

BibTex
----------
```
@misc{CryptoSMT-ref,
    author = {{Stefan Kölbl}},
    title = {{CryptoSMT: An easy to use tool for cryptanalysis of symmetric primitives}},
    note = {\url{https://github.com/kste/cryptosmt}},
}
```

