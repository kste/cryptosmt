# CryptoSMT

CryptoSMT is an easy to use tool for cryptanalysis of symmetric primitives likes 
block ciphers or hash functions. It is based on SMT/SAT solvers like STP, Boolector, 
CryptoMiniSat and provides a simple framework to use them for cryptanalytic techniques.

Some of the features are:
* Proof properties regarding the differential behavious of a primitive.
* Find the best linear/differential trails.
* Compute probability of a differential.
* Find preimages for hash functions.
* Recover a secret key.

The following primitives are supported by CryptoSMT at the moment: 

###### Block Ciphers
* Simon[3], 
* Speck[3], 
* Skinny[4],
* Present[5],
* Midori[6],
* LBlock[7],
* Sparx[8],
* Twine[9],
* Noekeon[10],
* Prince[11],
* Mantis[4],
* Speckey[8],
* Rectangle[12],
* Cham[13],
* CRAFT[21],
* TRIFLE[22]

###### Hash Functions
* Keccak[14]

###### Stream Ciphers
* Salsa[15], 
* ChaCha[16]

###### Authenticated Encryption Ciphers
* Ketje[17], 
* Ascon[18]

###### Message Authentication Codes
* Chaskey[19], 
* SipHash[20]

Please note that at the moment not all features are available for all ciphers. A
detailed description on the application of this tool on the SIMON block ciphers and
how a differential/linear model for SIMON can be constructed is given in [1].

## Installation

CryptoSMT requires you to have [STP](https://github.com/stp/stp),
[Cryptominisat](https://github.com/msoos/cryptominisat/) or [Bitwuzla](https://github.com/bitwuzla/bitwuzla) installed and setup the
paths to the binaries in `config.py`. Further it requires the `pyyaml` which you
can install using

    $ pip3 install pyyaml

The easiest way to get all the external tools to run is with the provided
Dockerfile. You can build a basic image using:

    cd docker/
    docker build -t cryptosmt .
    
This includes building minisat, cryptominisat, STP, boolector, Bitwuzla and all
dependencies. You can then run the image with:

    docker run -it cryptosmt

which gives you a ready to use setup of CryptoSMT.

## Testing

CryptoSMT uses `pytest` for testing. You can run the tests using the provided
Dockerfile:

    docker build -t cryptosmt .
    docker run --rm --entrypoint python3 cryptosmt -m pytest tests/

This will run both unit tests and integration tests that verify the tool's 
search functionality with different ciphers and solvers.

## Solvers

CryptoSMT supports multiple SMT solvers for finding characteristics. While STP is the default, both Boolector and Bitwuzla often provide significant performance improvements for deeper searches.

### Supported Solvers:
*   **STP (Default):** The original solver integrated in CryptoSMT.
*   **Boolector:** Often much faster than STP for bit-vector problems. Use with `--boolector`.
*   **Bitwuzla:** The successor to Boolector, generally offering the best performance. Use with `--bitwuzla`.
*   **ApproxMC:** Provides approximate model counting for **Probability Estimation (Mode 4)**. Use with `--approxmc`.

### Exact vs. Approximate Counting

When using **Mode 4**, CryptoSMT needs to count the number of characteristics for each weight.

1.  **Exact Counting (Default):** Uses `CryptoMiniSat` to find every single solution. This is extremely fast when the number of trails is small (e.g., < 100,000), but becomes impossible if there are millions or billions of solutions.
2.  **Approximate Counting (`--approxmc`):** Uses `ApproxMC` to estimate the number of solutions using hash-based sampling. 

**When to use ApproxMC:**
ApproxMC has a fixed overhead but scales exceptionally well with the size of the solution space. You should use it when analyzing complex differentials where you expect a very large number of trails (e.g., $2^{20}$ or more), as exact counting would take far too long. For simple problems with few solutions, exact counting remains the faster choice.

### Benchmarks (SIMON-32/64, 10 rounds)

The following table compares the performance (on a Macbook Pro M5) of the three solvers when searching for the minimum weight characteristic for 10 rounds of SIMON-32/64:

| Solver | Weight Found | Time Taken | Performance vs STP |
| :--- | :---: | :---: | :---: |
| **STP (Default)** | 25 | **281.95s** (~4.7 min) | Baseline |
| **Boolector** | 25 | **25.55s** | ~11x faster |
| **Bitwuzla** | 25 | **10.69s** | **~26x faster** |

To use Bitwuzla for the example above:
```bash
python3 cryptosmt.py --cipher simon --rounds 10 --wordsize 16 --bitwuzla
```

## Parallel Search

CryptoSMT supports parallel execution to utilize multiple CPU cores for faster searching. This is particularly effective for **Minimum Weight Search (Mode 0)** and **Probability Estimation (Mode 4)**.

*   **`--threads N`:** Specifies the number of threads to use. 
*   **Mode 0 (Min Weight):** Checks multiple weight values in a sliding window simultaneously.
*   **Mode 4 (Probability):** Distributes weight iterations across threads to count characteristics in parallel.

Example using 4 threads:
```bash
python3 cryptosmt.py --cipher simon --rounds 12 --wordsize 16 --threads 4
```

## Weight Encodings

You can choose different ways to encode the Hamming weight constraints in SMT. Depending on the cipher and solver, some encodings can be significantly faster:

*   **`bvplus` (Default):** Uses standard bit-vector addition. Best for modern solvers like Bitwuzla.
*   **`sorter`:** Uses a Bitonic Sorting Network. Often faster for pure SAT-based searches or very high weights.
*   **`totalizer`:** Uses a Unary Adder tree (Totalizer). A state-of-the-art encoding for cardinality constraints.

Example using the totalizer encoding:
```bash
python3 cryptosmt.py --cipher present --rounds 8 --wordsize 64 --weightencoding totalizer
```

## Logging and Progress

CryptoSMT provides visual feedback using `tqdm` progress bars and standard Python `logging`. You can control the verbosity of the output using the following flags:

*   **Default:** Shows general progress and found characteristics with a progress bar.
*   **`--verbose`:** Shows detailed information, including solver commands and raw output. Sets log level to `DEBUG`.
*   **`--quiet`:** Disables the progress bar and only shows found results or errors. Sets log level to `WARNING`.

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

## Adding a cipher to the CryptoSMT's cipher suites

Let's say you want to add "NewCipher" to the tool:
1. Make a copy from an example in "./ciphers/" which is similar to the design you want to analyze (for example if you want an
ARX, Speck might be a good start) and rename it to "NewCipher.py".
2. Modify the content of "NewCipher.py" to adapt it to your cipher (here it's best to look at some examples, as it depends a lot on design).
3. Update the file "cryptosmt.py": Add "NewCipher" in the import (line 8), and include it in the tool by adding it to the ciphersuite (line 25).
4. Run "python3 cryptosmt.py --cipher NewCipher" to see if it works.

## How does it work?

We can describe the process of the CryptoSMT as the following steps:
1. It creates an stp file which contains the SMT model of the differential cryptanaysis of the given cipher in CVC format (this file is placed in "./tmp/" folder)
2. After generation of SMT model in CVC format, it calls an SMT solver to solve the generated model. The STP is used by default as SMT solver. You can also use Boolector or Bitwuzla as SMT solver. 
3. The SMT model contains some inherent constraints which are used for modeling the differential propagation rules, and some additional constraints which are used to model the outside conditions like the fixed input/output differentials values. 
4. One of the additional constraints is the starting weight (of the differential probability) constraint. The first SMT model is generated with the starting weight, and this model is changed repeatedly by increasing the weight by one, and each time, its satisfiability is checked by an SMT solver. The goal is to find the minimum weight which makes the model satisfiable. 
5. If the SMT model is satisfiable for the first time, the weight (of the differential probability) which is used, is returned as the minimum weight (of the differential probability) as one of the output, and the process is stopped.

These processes are almost realted to the mod0, which is used to find the best differential with maximum (minimum) differential probablity (weight).

## Credits

Special thanks to [Ralph Ankele](https://github.com/TheBananaMan) and [Hosein Hadipour](https://github.com/hadipourh) for their extensive contributions!

## References
[1] [Observations on the SIMON block cipher family](http://eprint.iacr.org/2015/145)

[2] [Mind the Gap - A Closer Look at the Security of Block Ciphers against Differential Cryptanalysis](https://eprint.iacr.org/2018/689)

[3] [The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404)

[4] [The SKINNY Family of Block Ciphers and its Low-Latency Variant MANTIS](https://eprint.iacr.org/2016/660)

[5] [PRESENT: An Ultra-Lightweight Block Cipher](https://link.springer.com/chapter/10.1007/978-3-540-74735-2_31)

[6] [Midori: A Block Cipher for Low Energy (Extended Version)](https://eprint.iacr.org/2015/1142)

[7] [LBlock: A Lightweight Block Cipher](https://link.springer.com/chapter/10.1007/978-3-642-21554-4_19)

[8] [Design Strategies for ARX with Provable Bounds: SPARX and LAX (Full Version)](https://eprint.iacr.org/2016/984)

[9] [TWINE: A Lightweight Block Cipher for Multiple Platforms](https://pdfs.semanticscholar.org/26b9/d188fc506fb34247c57dc365547f961576d7.pdf)

[10] [Nessie Proposal: NOEKEON](http://gro.noekeon.org/Noekeon-spec.pdf)

[11] [PRINCE - A Low-latency Block Cipher for Pervasive Computing Applications (Full version)](https://eprint.iacr.org/2012/529)

[12] [RECTANGLE: A Bit-slice Lightweight Block Cipher Suitable for Multiple Platforms](https://eprint.iacr.org/2014/084)

[13] [CHAM: A Family of Lightweight Block Ciphers for Resource-Constrained Devices](https://link.springer.com/chapter/10.1007/978-3-319-78556-1_1)

[14] [The Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf)

[15] [The Salsa20 family of stream ciphers](https://cr.yp.to/snuffle/salsafamily-20071225.pdf)

[16] [ChaCha, a variant of Salsa20](https://cr.yp.to/chacha/chacha-20080128.pdf)

[17] [CAESAR submission: Kђѡїђ v2](https://competitions.cr.yp.to/round3/ketjev2.pdf)

[18] [Ascon v1.2 Submission to the CAESAR Competition](https://competitions.cr.yp.to/round3/asconv12.pdf)

[19] [Chaskey: An Efficient MAC Algorithm for 32-bit Microcontrollers](https://eprint.iacr.org/2014/386)

[20] [SipHash: a fast short-input PRF](https://131002.net/siphash/siphash.pdf)

[21] [CRAFT: Lightweight Tweakable Block Cipher with Efficient Protection Against DFA Attacks](https://tosc.iacr.org/index.php/ToSC/article/view/7396)

[22] [TRIFLE](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/round-1/spec-doc/trifle-spec.pdf)


## BibTex
```
@misc{CryptoSMT-ref,
    author = {{Stefan Kölbl}},
    title = {{CryptoSMT: An easy to use tool for cryptanalysis of symmetric primitives}},
    note = {\url{https://github.com/kste/cryptosmt}},
}
```
