# Token Escalation Attack on Datavant-Like Match Keys

This repository contains the implementation of a **Escalation Attack** framework, developed as part of the master's thesis **"Record Linkage with Match Key Algorithms: Is it secure?"**.

## Overview

Privacy-Preserving Record Linkage (PPRL) systems often use multiple, redundant "match keys" (tokens) to link patient records across databases. This project demonstrates that providing correlated tokens (e.g., a low-entropy Soundex token alongside a high-entropy Name token) introduces a critical vulnerability: **entropy dependencies**.

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
* ```pycryptodome```: for AES-256 and HMAC operations.
* ```jellyfish```: for Soundex encoding.
* ```Faker```: for generating synthetic German/US datasets.
* ```pandas```: for data manipulation.
* ```gender-guesser```: for imputing gender in real-world datasets.

## Repository Structure

```text
.
├── attack/                  # Main attack function
├── cleaned_data/            # Normalised and standardised data for usage as reference dataset or match key creation
│   ├── ESSnet/              # CIS and Census datasets
│   ├── de/                  # German datasets
│   └── us                   # US datasets (NVR and OVR) (zipped due to size)
├── dictionaries/            # Static dictionaries form web search
│   ├── de/                  # Lists of first names, last names and addresses specific to Germany
│   ├── us/                  # Lists of first names, last names and addresses specific to the US
│   └── results/             # Results from the dictionary attack
│   │   ├── ESSnet/          # Results using the CIS datasets with US-specific static dictionary
│   │   ├── de/              # Results using the DA10 dataset with German-specififc static dictioanrey
│   │   └── us/              # Results using the NVR datasets with US-specific static dictionary
├── match_keys/              # Folder containing all generated match keys and scripts to generate them
│   ├── ESSnet/              # Match keys for CIS dataset
│   ├── de/                  # Match keys for generated German datasets (D0, DA1, DB1, DA10, DB10, DA50, DB50) (with variations including only one DOB)
│   ├── us                   # Match keys for NVR dataset (zipped due to size) (with variations including only one DOB or the exclusion of house numbers)
│   └── match_key_creation/  # Scripts for generating match keys (with and without secret salt)
├── old_approaches/          # Folder containing scripts and results from the first and reworked approaches for the development of the final attack
├── raw_data/                # Folder containing the raw data used to create the cleaned datasets and scripts for cleaning
│   ├── ESSnet/              # Raw data from ESSnet for CIS and Census datasets
│   ├── de/                  # Raw data generated from Faker using different sets (e.g., 1234, 4321, 5678) and the German locale (de_DE)
│   ├── us                   # Raw data from NVR and OVR datasets  (zipped due to size) 
│   ├── data_cleaning/       # Folder containing scripts for cleaning specific datasets
│   └── data_simulation/     # Folder containing scripts for data simulation
├── results/                 # Folder containing all the results of the final attack
│   ├── brute_force/         # Results from the brute-force mode
│   │   ├── 24CPUCores/      # Results from the brute-force attack on the German dataset D0 using 24 CPU cores
│   │   └── 128CPUCores/     # Results from the brute-force attack on the German dataset D0 using 128 CPU cores
│   └── dictionary/          # Results from the dictionary mode
│       ├── baseline/        # Results from the baseline dictionary attack
│       ├── de/              # Results from the dictionary attacks on German simulated datasets (with 500, 1000 and 2000 reference values)
│       └── us/              # Results from the dictionary attacks on the North Carolina dataset (with 500, 1000 and 2000 reference values)
├── scripts/                 # Folder containing helper scripts for key generation, value counting or replacing DOBs for brute-force attack testing
├── generated_key            # File containing the used AES keys for encryption and decryption
└── README.md
```

## Usage Guide. Reproducing the Results

**Step 1: Dataset Creation (Simulation)**
Generate a synthetic dataset with realistic name distributions.

```bash
python raw_data/data_simulation/gen_dataset.py
```
Respective changes regarding seeds (e.g., 1234, 4321, 5678) and locale ("de_DE" or "en_US") must be adjusted within the code directly.

**Step 2: Data Cleaning & Normalisation**

Prepare the data for tokenisation by standardising formats (e.g., removing special characters, formatting DOB to YYYYMMDD).
Note that, depending on which datasets should be cleaned, the respective script needs to be run:

* ```cleandata_essnet.py```: for cleaning the datasets CIS or Census from ESSnet.
* ```cleandata_german.py```: for cleaning all simulated German datasets.
* ```cleandata_nc.py```: for cleaning NVR (North Carolina) data.
* ```cleandata_ohio.py```: for cleaning OVR (Ohio) data.
* ```clean_address.pyr```: for removing house numbers from the addresses.

**Step 3: Tokenisation (Encryption)**

Simulate the "Linkage Unit" (LU). This script converts plaintext records into encrypted match keys (T1…T9) using a Master Salt (HMAC) and a Site Key (AES-128 or -256).

```bash
python match_keys/match_key_Creation/datavant-matchkey-algo-nosalt.py \
  --in data/simulated/dataset_D0_clean.csv \
  --out data/encrypted/tokens_D0.csv \
  --site-key "dc31ebf7f2879ea343d5b08d1e912b88f413c6c50ac49e1386136758a59d64d7" \
```
Output: A CSV file containing only the encrypted tokens (no plaintext). This represents the data leak.

**Step 4: Execution of the Attack**

Run the main attack ```multiple_attack_multproc_nomemo.py``` script to re-identify the encrypted tokens.
When deciding which columns to use for attacking the match keys, note that the written sequence of columns decides the attack path.

### A. Dictionary Mode (Recommended)

Uses a reference dictionary (e.g., Top-N names) to pivot through the tokens.

```bash
python attack/multiple_attack_multproc_nomemo.py \
  --in data/encrypted/tokens_D0.csv \
  --out results/attack_results_D0.csv \
  --dist-file data/dictionaries/known_data_distribution.csv \
  --top-n 500 \
  --columns T1,T2,T7,T4,T3,T9 \
  --lang de \
  --site-key "dc31ebf7f2879ea343d5b08d1e912b88f413c6c50ac49e1386136758a59d64d7" 
```

### B. Brute-Force Mode (Name Generator)

Uses the recursive Soundex generator to reverse-engineer names without a dictionary.

```bash
python attack/multiple_attack_multproc_nomemo.py \
  --in data/encrypted/tokens_D0.csv \
  --out results/bf_results_D0.csv \
  --columns T2,T1,T7,T4 \
  --bruteforce \
  --site-key "dc31ebf7f2879ea343d5b08d1e912b88f413c6c50ac49e1386136758a59d64d7"
  --max-fn-len 8 --max-ln-len 8
```

## Arguments Explanation
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
| `--fix-dob` | ❌ | `False` |  Forces the attack to only check `20000101` as the DOB. |
```

## Interpreting Results

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

This attack framework is a Proof of Concept (PoC) for academic research. It is designed to audit the security of PPRL systems using synthetic or publicly available data. It should not be used to target real individuals or protected health information (PHI) without explicit authorisation.
