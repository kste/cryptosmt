# CryptoSMT
=========

CryptoSMT is an easy to use tool for cryptanalysis of symmetric primitives likes 
block ciphers or hash functions. It is based on SMT/SAT solvers like STP, Boolector, 
CryptoMiniSat and provides a simple framework to use them for cryptanalytic techniques.

Some of the features are:
* Proof properties regarding the differential behavious of a primitive.
* Find the best linear/differential trails.
* Compute probability of a differential.
* Find preimages for hash functions.
* Recover a secret key.

The following primitives are supported by CryptoSMT at the moment: Simon, Speck, Keccak,
Ketje, Chaskey, SipHash, Salsa, ChaCha, Ascon, Gimli, Present

Please note that at the moment not all features are available for all ciphers. A
detailed description on the application of this tool on the SIMON block ciphers and
how a differential/linear model for SIMON can be constructed is given in [1].

You can find some additional information on the [project website](https://kste.dk/cryptosmt.html).

## Installation

CryptoSMT requires you to have [STP](https://github.com/stp/stp) and
[Cryptominisat](https://github.com/msoos/cryptominisat/) installed and setup the
paths to the binaries in `config.py`. Further it requires the `pyyaml` which you
can install using

    $ pip3 install pyyaml

The easiest way to get all the external tools to run is with the provided
Dockerfile. You can build a basic image using:

    cd docker/
    docker build -t cryptosmt .
    
This includes building minisat, cryptominisat, STP, boolector and all
dependencies. You can then run the image with:

    docker run -it cryptosmt

which gives you a ready to use setup of CryptoSMT.

## Usage

As an example we will look at how CryptoSMT can be used to find the optimal
differential characteristics for the block cipher Simon.

Running the command
    
    $ python3 cryptosmt.py --cipher simon --rounds 8 --wordsize 16
    
will start the search for the optimal trail and you will see as output

    simon - Rounds: 8 Wordsize: 16
    ---
    Weight: 0 Time: 0.0s
    Weight: 1 Time: 0.08s
    Weight: 2 Time: 0.16s
    Weight: 3 Time: 0.44s
    Weight: 4 Time: 0.74s
    Weight: 5 Time: 0.89s
    ...
          
CryptoSMT tries to find a differential trail with a given weight `w_i`. 
If no such trail exists `w_i` is incremented and the search continues. 
In this case the best trail has a weight of `18` and can be quickly 
found:

    Characteristic for simon - Rounds 8 - Wordsize 16 - Weight 18 - Time 13.15s
    Rounds  x       y       w
    -------------------------------
    0       0x0040  0x0191  -2
    1       0x0011  0x0040  -4
    2       0x0004  0x0011  -2
    3       0x0001  0x0004  -2
    4       0x0000  0x0001  -0
    5       0x0001  0x0000  -2
    6       0x0004  0x0001  -2
    7       0x0011  0x0004  -4
    8       0x0040  0x0011  none

    Weight: 18
          
CryptoSMT prints out the difference in the two state words `x_i`, `y_i` 
and the probability for the transition between two rounds `w_i`.

## References
[1] [Observations on the SIMON block cipher family](http://eprint.iacr.org/2015/145)

[2] [Mind the Gap - A Closer Look at the Security of Block Ciphers against Differential Cryptanalysis](https://eprint.iacr.org/2018/689)

## BibTex
```
@misc{CryptoSMT-ref,
    author = {{Stefan Kölbl}},
    title = {{CryptoSMT: An easy to use tool for cryptanalysis of symmetric primitives}},
    note = {\url{https://github.com/kste/cryptosmt}},
}
```
