# Token Escalation Attack on Datavant-Like Match Keys

This repository contains the implementation of a **Token Escalation Attack** framework, developed as part of the Master's Thesis **"Record Linkage with Match Key Algorithms: Is it secure?"**.

## Overview

Privacy-Preserving Record Linkage (PPRL) systems often use multiple, redundant "match keys" (tokens) to link patient records across databases. This project demonstrates that providing correlated tokens (e.g., a low-entropy Soundex token alongside a high-entropy Name token) introduces a critical vulnerability: **Entropy Dependencies**.

This framework implements a cryptanalytic attack that:
1.  **Exploits** low-entropy tokens (T1, T2) to recover partial attributes (Gender, DOB, Soundex).
2.  **Pivots** (Escalates) this information to reduce the search space for high-entropy tokens (T4).
3.  **Re-identifies** individuals in encrypted datasets using both Dictionary and Brute-Force methods.

## Installation & Requirements

The framework is built in Python 3.13+. It relies on multiprocessing for performance.

```bash
# Clone the repository
git clone [https://github.com/BettyxMue/master-thesis-match-keys-datavant-attack.git](https://github.com/BettyxMue/master-thesis-match-keys-datavant-attack.git)
cd master-thesis-match-keys-datavant-attack

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Key Dependencies
* ```pycryptodome```: For AES-256 and HMAC operations.
* ```jellyfish```: For Soundex encoding.
* ```Faker```: For generating synthetic German/US datasets.
* ```pandas```: For data manipulation.
* ```gender-guesser```: For imputing gender in real-world datasets.

## Repository Structure

```text
.
├── data/
│   ├── dictionaries/      # Frequency lists (names, streets) for the dictionary attack
│   ├── simulated/         # Generated synthetic datasets (Plaintext)
│   └── encrypted/         # Tokenised datasets (Target for the attack)
├── logs/                  # Execution logs
├── results/               # Attack output (CSV files with re-identified records)
├── src/
│   ├── generate_data.py   # Step 1: Simulates entities (Faker)
│   ├── clean_data.py      # Step 2: Normalises raw data (HIPAA rules)
│   ├── encrypt_tokens.py  # Step 3: Generates Datavant-like Match Keys
│   ├── attack.py          # Step 4: The Main Attack Framework
│   └── utils/             # Helper functions (Soundex maps, Generators)
└── README.md
```

## Usage Guide. Reproducing the Results

**Step 1: Dataset Creation (Simulation)**
Generate a synthetic dataset with realistic name distributions.

```bash
python src/generate_data.py --locale de_DE --count 10000 --seed 1234 --out data/simulated/dataset_D0.csv
```

**Step 2: Data Cleaning & Normalisation**

Prepare the data for tokenisation by standardising formats (e.g., removing special characters, formatting DOB to YYYYMMDD).

```bash
python src/clean_data.py --in data/simulated/dataset_D0.csv --out data/simulated/dataset_D0_clean.csv
```

**Step 3: Tokenisation (Encryption)**

Simulate the "Linkage Unit" (LU). This script converts plaintext records into encrypted match keys (T1…T9) using a Master Salt (HMAC) and a Site Key (AES-256).

```bash
python src/encrypt_tokens.py \
  --in data/simulated/dataset_D0_clean.csv \
  --out data/encrypted/tokens_D0.csv \
  --site-key "dc31ebf7f2879ea343d5b08d1e912b88f413c6c50ac49e1386136758a59d64d7" \
  --master-salt "e0b28255c5071c0121159"
```
Output: A CSV file containing only the encrypted tokens (no plaintext). This represents the data leak.

**Step 4: Execution of the Attack**

Run the main attack ```multiple_attack_multproc_nomemo.py``` script to re-identify the encrypted tokens.

### A. Dictionary Mode (Recommended)

Uses a reference dictionary (e.g., Top-N names) to pivot through the tokens.

```bash
python src/attack.py \
  --in data/encrypted/tokens_D0.csv \
  --out results/attack_results_D0.csv \
  --dist-file data/dictionaries/known_data_distribution.csv \
  --top-n 500 \
  --columns T1,T2,T7,T4,T3,T9 \
  --lang de \
  --site-key "dc31ebf7f2879ea343d5b08d1e912b88f413c6c50ac49e1386136758a59d64d7" \
  --master-salt "e0b28255c5071c0121159"
```

### B. Brute-Force Mode (Name Generator)

Uses the recursive Soundex generator to reverse-engineer names without a dictionary.

```bash
python src/attack.py \
  --in data/encrypted/tokens_D0.csv \
  --out results/bf_results_D0.csv \
  --columns T2,T1,T7,T4 \
  --bruteforce \
  --site-key "dc31ebf7f2879ea343d5b08d1e912b88f413c6c50ac49e1386136758a59d64d7" \
  --master-salt "e0b28255c5071c0121159" \
  --max-fn-len 8 --max-ln-len 8
```

# Arguments Explanation
```markdown
| Argument | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `--in` | ✅ | - | Path to the input CSV file containing encrypted tokens. |
| `--out` | ✅ | - | Path where the result file (CSV) will be saved. |
| `--columns` | ✅ | - | Comma-separated list of tokens to attack (e.g., `T1,T2,T7,T4`). Determines the attack path. |
| `--site-key` | ✅ | - | The 32-byte AES-256 key (Hex or UTF-8) used for site-specific encryption. |
| `--dist-file` | ❌ | `""` | Path to a distribution CSV (first_name, last_name, address) for the dictionary attack. |
| `--top-n` | ❌ | `500` | Number of most frequent values to load from the dictionary. |
| `--lang` | ❌ | `de` | Language mode for hardcoded dictionaries (`de` or `us`). |
| `--master-salt` | ❌ | `""` | The master salt (Hex or UTF-8) used for HMAC hashing. |
| `--bruteforce` | ❌ | `False` | Switch to Pure Brute-Force Mode (Generator) instead of using reference lists. |
| `--max-fn-len` | ❌ | `8` | (Brute-force only) Max length for generated First Names. |
| `--max-ln-len` | ❌ | `8` | (Brute-force only) Max length for generated Last Names. |
| `--bf-max-preimages` | ❌ | `100000` | (Brute-force only) Limit on name candidates generated per Soundex code to prevent OOM errors. |
| `--excl-nr` | ❌ | `False` | If set, excludes house numbers from the T9 (Address) pivot to save time. |
| `--fix-dob` | ❌ | `False` | Debug option: Forces the attack to only check `20000101` as the DOB. |
```

# Interpreting Results

The attack script outputs a log file and a CSV result file.
* **RT (Recovered Tokens):** The absolute number of unique tokens successfully re-identified.
* **RR (Re-identification Rate):** The percentage of the target population compromised.
* **ET (Execution Time):** The wall-clock time taken for that specific stage.
* **H (Hashes):** The total number of cryptographic hash computations performed.
  
Example Output:
```bash
[*] Attacking T1 (Parallel)...
    -> Found 8617 T1 preimages (50.24s). Hashes: 897,390,000
[*] Attacking T2 via T1 (Parallel)...
    -> Found 5373 T2 preimages (0.30s). Hashes: 162,416
...
```

## Ethical Considerations

This software is a Proof of Concept (PoC) for academic research. It is designed to audit the security of PPRL systems using synthetic or publicly available data. It should not be used to target real individuals or protected health information (PHI) without explicit authorisation.
