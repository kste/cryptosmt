# CryptoSMT

**CryptoSMT** is a powerful and versatile tool for the cryptanalysis of symmetric primitives, including block ciphers, hash functions, and stream ciphers. By leveraging modern SMT (Satisfiability Modulo Theories) and SAT solvers, CryptoSMT provides an automated environment for proving security properties and discovering optimal cryptanalytic trails.

---

### Key Capabilities

*   **Optimal Trail Discovery**: Automatically find the best linear and differential characteristics for a wide range of ciphers.
*   **Probability Estimation**: Accurately compute the probability of complex differentials using exact or approximate model counting.
*   **High-Performance Engine**: Built-in support for high-performance solvers like **Bitwuzla**, **Boolector**, and **STP**.
*   **Parallel Search**: Fully parallelized execution engine to utilize all available CPU cores.
*   **Extensible Architecture**: Modular design based on an automated `AbstractCipher` framework, making it easy to add support for new primitives.
---

### Supported Primitives

CryptoSMT includes models for a broad suite of modern cryptographic designs:

| Category | Primitives |
| :--- | :--- |
| **Block Ciphers** | Simon, Speck, Skinny, Present, Midori, LBlock, Twine, Sparx, Noekeon, Prince, Mantis, Rectangle, Cham, CRAFT, TRIFLE |
| **Hash Functions** | Keccak (SHA-3), Ketje |
| **Stream Ciphers** | Salsa20, ChaCha20 |
| **Authenticated Encryption** | Ascon, Ketje |
| **MACs / PRFs** | Chaskey, SipHash |

---

## 🛠️ Getting Started

### Installation via Docker (Recommended)

The easiest way to deploy CryptoSMT with all high-performance solvers (STP, Bitwuzla, Boolector, ApproxMC) is using Docker:

```bash
# Build the comprehensive cryptanalysis image
docker build -t cryptosmt -f docker/Dockerfile .

# Run the interactive environment
docker run -it cryptosmt
```

### Local Installation

CryptoSMT requires Python 3.10+ and at least one SMT solver. 

1.  Install dependencies:
    ```bash
    pip3 install pyyaml tqdm
    ```
2.  Install solvers (STP, Bitwuzla, or Boolector) and configure their paths in `config.py`.

---

## 🧪 Usage Examples

### Finding an Optimal Differential Trail
To find the minimum weight differential characteristic for **Simon-32/64** with 8 rounds:
```bash
python3 cryptosmt.py --cipher simon --rounds 8 --wordsize 16
```

### Estimating Differential Probability (Mode 4)
Uses **Parallel Search** for high-speed probability estimation:
```bash
python3 cryptosmt.py --inputfile examples/simon/simon32_13rounds_diff.yaml --threads 4
```

---

## 🔬 Advanced Features

### Solvers
CryptoSMT supports multiple backend solvers. While **STP** is the default, **Bitwuzla** generally provides the best performance for modern cryptanalysis.

### Supported Solvers:
*   **STP (Default):** The original solver integrated in CryptoSMT.
*   **Boolector:** Optimized for bit-vector problems. Use with `--boolector`.
*   **Bitwuzla:** The high-performance successor to Boolector. Use with `--bitwuzla`.
*   **ApproxMC:** Provides approximate model counting for massive solution spaces in **Mode 4**. Use with `--approxmc`.

### Exact vs. Approximate Counting
When using **Mode 4**, CryptoSMT needs to count the number of characteristics for each weight.

1.  **Exact Counting (Default):** Uses `CryptoMiniSat` to find every solution. Fast for small trail sets (< 100k).
2.  **Approximate Counting (`--approxmc`):** Uses `ApproxMC` for hash-based sampling. Essential for complex differentials with millions or billions of solutions.

---

### Parallel Search

CryptoSMT supports parallel execution to utilize multiple CPU cores for faster searching. This is particularly effective for **Minimum Weight Search (Mode 0)** and **Probability Estimation (Mode 4)**.

*   **`--threads N`:** Specifies the number of threads to use. 
*   **Mode 0 (Min Weight):** Checks multiple weight values in a sliding window simultaneously.
*   **Mode 4 (Probability):** Distributes weight iterations across threads to count characteristics in parallel.

Example using 4 threads:
```bash
python3 cryptosmt.py --cipher simon --rounds 12 --wordsize 16 --threads 4
```

---

### Weight Encodings

You can choose different ways to encode the Hamming weight constraints in SMT. Depending on the cipher and solver, some encodings can be significantly faster:

*   **`bvplus` (Default):** Uses standard bit-vector addition. Best for modern solvers like Bitwuzla.
*   **`sorter`:** Uses a Bitonic Sorting Network. Often faster for pure SAT-based searches or very high weights.
*   **`totalizer`:** Uses a Unary Adder tree (Totalizer).

Example using the totalizer encoding:
```bash
python3 cryptosmt.py --cipher present --rounds 8 --wordsize 64 --weightencoding totalizer
```

---

## 📊 Benchmarks (SIMON-32/64, 10 rounds)

The following table compares the performance (on a Macbook Pro M5) of the three solvers when searching for the minimum weight characteristic for 10 rounds of SIMON-32/64:

| Solver | Weight Found | Time Taken | Performance vs STP |
| :--- | :---: | :---: | :---: |
| **STP (Default)** | 25 | **281.95s** (~4.7 min) | Baseline |
| **Boolector** | 25 | **25.55s** | ~11x faster |
| **Bitwuzla** | 25 | **10.69s** | **~26x faster** |

---

## 🛡️ Logging and Progress

CryptoSMT provides visual feedback using `tqdm` progress bars and standard Python `logging`. 

*   **Default:** Shows general progress and found characteristics with a progress bar.
*   **`--verbose`:** Shows detailed information, including solver commands and raw output. Sets log level to `DEBUG`.
*   **`--quiet`:** Disables the progress bar and only shows found results or errors. Sets log level to `WARNING`.

---

## Credits

Special thanks to [Ralph Ankele](https://github.com/TheBananaMan) and [Hosein Hadipour](https://github.com/hadipourh) for their extensive contributions!

## BibTex
```
@misc{CryptoSMT-ref,
    author = {{Stefan Kölbl}},
    title = {{CryptoSMT: An easy to use tool for cryptanalysis of symmetric primitives}},
    note = {\url{https://github.com/kste/cryptosmt}},
}
```
