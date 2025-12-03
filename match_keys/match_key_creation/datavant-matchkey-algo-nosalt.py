#!/usr/bin/env python3
"""
Datavant-like Token Generation Script
Master Thesis: Record Linkage with Match Key Algorithms - Is it secure?
Author: Babett Müller

Description:
    This script simulates the "Tokenization" phase of a Privacy-Preserving Record Linkage (PPRL)
    process similar to Datavant. It reads a plaintext CSV file containing Personally Identifiable 
    Information (PII), normalizes the data according to specific rules (HIPAA/Safe Harbor compliance), 
    and generates encrypted "Match Key" tokens.

    The process follows three main steps:
    1. Normalization: Cleaning and standardizing raw PII (e.g., dates to YYYYMMDD, names to lowercase).
    2. Feature Extraction: Deriving specific features like Soundex codes or initials.
    3. Tokenization: Constructing token strings (e.g., "LastName|Initial|Gender|DOB") and 
       encrypting them using a simplified Datavant schema: Base64(AES-ECB(SHA-256(Input))).

Usage:
    python3 datavant-matchkey-algo-nosalt.py --in input.csv --out output.csv --site-key "YOUR_KEY"
"""

import argparse
import base64
import csv
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from jellyfish import soundex
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ==============================================================================
# 1. NORMALIZATION UTILITIES
# ==============================================================================
# These functions ensure that data from different sources (e.g., "Smith" vs "smith ")
# results in the exact same string before hashing.

def norm_str(s: Optional[str]) -> str:
    """
    Removes all non-alphanumeric characters and converts to lowercase.
    Example: "O'Connor!" -> "oconnor"
    """
    if s is None:
        return ""
    return "".join(ch for ch in s.strip().lower() if ch.isalnum())

def norm_name(s: Optional[str]) -> str:
    """
    Normalizes a name string. Currently acts as a wrapper for norm_str
    but can be extended for name-specific logic (e.g. removing suffixes).
    """
    return norm_str(s).strip().lower()

def first_initial(name: Optional[str]) -> str:
    """
    Extracts the first character of a normalized name.
    Returns empty string if name is missing.
    """
    n = norm_name(name).strip().lower()
    return n[0] if n else ""

def first_n(name: Optional[str], n: int) -> str:
    """
    Extracts the first N characters of a normalized name.
    Used for tokens like T7 (First 3 letters).
    """
    nm = norm_name(name).strip().lower()
    return nm[:n] if nm else ""

def norm_sex(sx: Optional[str]) -> str:
    """
    Standardizes gender/sex to a single character code.
    Mapping:
        'm', 'male' -> 'm'
        'f', 'female' -> 'f'
        Otherwise   -> 'u' (Unknown)
    """
    sx = (sx or "").strip().lower()
    if sx in ("m", "male"): return "m"
    if sx in ("f", "female"): return "f"
    return "u"

def norm_dob(d: Optional[str]) -> str:
    """
    Parses various date string formats and standardizes them to 'YYYYMMDD'.
    Supported formats: YYYY-MM-DD, DD.MM.YYYY, MM/DD/YYYY, YYYY/MM/DD, YYYYMMDD
    
    Returns:
        String 'YYYYMMDD' or empty string on failure.
    """
    if not d or not str(d).strip():
        return ""
    s = str(d).strip()
    fmts = ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y%m%d")
    for f in fmts:
        try:
            return datetime.strptime(s, f).strftime("%Y%m%d")
        except ValueError:
            pass
    # Fallback: Check if it already looks like YYYYMMDD
    if len(s) == 8 and s.isdigit():
        return s
    return ""

def year_of_birth(d: Optional[str]) -> str:
    """
    Extracts the 4-digit year from a date string.
    """
    ymd = norm_dob(d)
    return ymd[:4] if ymd else ""

def zip3(z: Optional[str]) -> str:
    """
    Extracts the first 3 digits of a ZIP code (HIPAA Safe Harbor standard).
    Example: "12345" -> "123"
    """
    digits = "".join(ch for ch in str(z or "") if ch.isdigit())
    return digits[:3]

def norm_phone(p: Optional[str]) -> str:
    """
    Normalizes a phone number by stripping all non-digit characters.
    """
    return "".join(ch for ch in str(p or "") if ch.isdigit())

def norm_email(e: Optional[str]) -> str:
    """
    Simple lowercasing and trimming for email addresses.
    """
    return (e or "").strip().lower()

def norm_address(a: Optional[str]) -> str:
    """
    Normalizes address strings (alphanumeric only, lowercase).
    """
    return norm_str(a).strip().lower()

# ==============================================================================
# 2. CRYPTOGRAPHIC FUNCTIONS
# ==============================================================================
# Implements the "Site Token" generation: Base64(AES(SHA256(Data)))

def parse_aes128_256_key(s: str) -> bytes:
    """
    Parses the provided site key. Accepts Hex strings or raw UTF-8 strings.
    Validates that the key length is appropriate for AES-128 (16 bytes) 
    or AES-256 (32 bytes).
    """
    try:
        key = bytes.fromhex(s)
    except ValueError:
        key = s.encode("utf-8")
    if len(key) != 32 and len(key) != 16:
        raise ValueError(f"Site key must be 16 or 32 bytes for AES-128/256; got {len(key)} bytes")
    return key

def master_sha256(token_input: str) -> bytes:
    """
    Computes the intermediate 'Master Token' (Hash).
    Standard: SHA-256 over the normalized input string (UTF-8 encoded).
    
    Output: 32 bytes (binary)
    """
    return hashlib.sha256(token_input.encode("utf-8")).digest()

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """
    Encrypts the data using AES in ECB mode.
    
    Note: ECB mode requires the input data length to be a multiple of the block size.
    Since SHA-256 output is always 32 bytes, and AES block size is 16 bytes,
    no padding is strictly required here for SHA-256 inputs.
    """
    if key is not None and len(key) == 16:
        """AES-128-ECB encrypt. Data must be a multiple of 16 bytes (SHA-256 is 32)."""
        if len(data) % 16 != 0:
            raise ValueError("Plaintext length must be a multiple of 16 bytes for ECB.")
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)
    elif key is not None and len(key) == 32:
        """AES-256-ECB encrypt. Data must be a multiple of 32 bytes (SHA-256 is 32)."""
        if len(data) % 32 != 0:
            raise ValueError("Plaintext length must be a multiple of 32 bytes for ECB.")
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)
    else:
        raise ValueError("Key must be either None or does not have a valid length (16 or 32 bytes).")

def site_token(site_key: bytes, token_input: str) -> str:
    """
    The core tokenization workflow.
    1. Hash the input string (SHA-256).
    2. Encrypt the hash with the Site Key (AES-ECB).
    3. Encode the result in Base64 for text transport.
    
    Args:
        site_key: The cryptographic key for this specific site.
        token_input: The normalized string (e.g., "smith|j|m|19800101").
        
    Returns:
        A Base64 string representing the encrypted token.
    """
    master = master_sha256(token_input)
    ct = aes_ecb_encrypt(site_key, master)
    return base64.b64encode(ct).decode("ascii")

# ==============================================================================
# 3. TOKEN RECIPES & CONSTRUCTION
# ==============================================================================

def recipe_inputs(row: Dict[str, Any]) -> Dict[str, str]:
    """
    Extracts and normalizes all necessary fields from a raw CSV row.
    Also computes derived features like Soundex codes.
    
    Args:
        row: A dictionary representing a single row from the input CSV.
        
    Returns:
        A dictionary containing normalized values (fn, ln, dob...) and 
        derived features (fi, f3, sdx_fn...).
    """
    # 1. Normalize Raw Fields
    fn = norm_name(row.get("first_name"))
    ln = norm_name(row.get("last_name"))
    dob = norm_dob(row.get("dob"))
    yob = year_of_birth(row.get("dob"))
    sx  = norm_sex(row.get("sex"))
    zp = zip3(row.get("zip"))
    ph = norm_phone(row.get("phone"))
    em = norm_email(row.get("email"))
    addr = norm_address(row.get("address"))

    # 2. Derived Features for Match Keys
    fi = first_initial(row.get("first_name"))       # First Initial
    f3 = first_n(row.get("first_name"), 3)          # First 3 letters
    sdx_fn = soundex(row.get("first_name"))         # Soundex of First Name
    sdx_ln = soundex(row.get("last_name"))          # Soundex of Last Name   

    return dict(
        fn=fn, ln=ln, dob=dob, yob=yob, sx=sx, zp=zp, ph=ph, em=em, addr=addr,
        fi=fi, f3=f3, sdx_fn=sdx_fn, sdx_ln=sdx_ln
    )

def build_token_inputs(v: Dict[str, str]) -> Dict[str, str]:
    """
    Constructs the raw "Match Key" strings based on defined recipes.
    Only constructs a token if all required fields for that token are present.
    
    Args:
        v: The dictionary of normalized values from recipe_inputs().
        
    Returns:
        A dictionary { 'TokenName': 'RawString' }.
        Example: { 'T1': 'miller|t|m|19800101' }
    """
    tokens: Dict[str, str] = {}
    
    fn, ln, dob, sx, zp = v["fn"], v["ln"], v["dob"], v["sx"], v["zp"]
    fi, f3, sdx_fn, sdx_ln = v["fi"], v["f3"], v["sdx_fn"], v["sdx_ln"]
    ph, em, addr, yob = v["ph"], v["em"], v["addr"], v["yob"]

    # T1: Last Name + First Initial + Sex + DOB
    # Purpose: Strict match on Last Name/DOB, loose on First Name.
    if v["ln"] and v["fi"] and v["sx"] and v["dob"]:
        tokens["T1"] = "|".join([v["ln"], v["fi"], v["sx"], v["dob"]])

    # T2: Soundex(Last) + Soundex(First) + Sex + DOB
    # Purpose: Phonetic match to catch spelling errors.
    if v["sdx_ln"] and v["sdx_fn"] and v["sx"] and v["dob"]:
        tokens["T2"] = "|".join([v["sdx_ln"], v["sdx_fn"], v["sx"], v["dob"]])

    # T3: Last Name + First Name + DOB + ZIP3
    # Purpose: Strict name match, loose location (ZIP3).
    if v["ln"] and v["fn"] and v["dob"] and v["zp"]:
        tokens["T3"] = "|".join([v["ln"], v["fn"], v["dob"], v["zp"]])

    # T4: Last Name + First Name + Sex + DOB
    # Purpose: The "Gold Standard" strict token (High Entropy).
    if v["ln"] and v["fn"] and v["sx"] and v["dob"]:
        tokens["T4"] = "|".join([v["ln"], v["fn"], v["sx"], v["dob"]])

    # T7: Last Name + First 3 Chars + Sex + DOB
    # Purpose: Handles slight variations/shortening of First Name.
    if v["ln"] and v["f3"] and v["sx"] and v["dob"]:
        tokens["T7"] = "|".join([v["ln"], v["f3"], v["sx"], v["dob"]])

    # T9: First Name + Address
    # Purpose: Household linkage (very fuzzy/experimental).
    if v["fn"] and v["addr"]:
        tokens["T9"] = "|".join([v["fn"], v["addr"]])

    # -- Placeholder for unused tokens (T5, T16, T22, T40) --
    # These tokens often require data not present in standard datasets (e.g., SSN)
    # or were not part of the scope of this thesis.

    return tokens

# ==============================================================================
# 4. MAIN PROCESSING LOOP
# ==============================================================================

def process_csv(infile: str, outfile: str, site_key_str: str, id_column: Optional[str] = None):
    """
    Orchestrates the reading, processing, and writing of the dataset.
    
    Args:
        infile: Path to input CSV.
        outfile: Path to output CSV.
        site_key_str: The cryptographic key (Hex or String).
        id_column: (Optional) Name of the column to use as record ID.
    """
    # Parse key once
    site_key = parse_aes128_256_key(site_key_str)

    # Read input CSV
    with open(infile, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    token_names: List[str] = []
    outputs: List[Dict[str, str]] = []

    # Process rows
    for i, row in enumerate(rows):
        # 1. Determine ID
        rid = row.get(id_column) if id_column and id_column in row else str(i)

        # 2. Normalize & Extract Features
        v = recipe_inputs(row)

        # 3. Build Match Key Strings
        token_inputs = build_token_inputs(v)

        # 4. Encrypt Tokens
        token_values: Dict[str, str] = {}
        for tname, tinput in token_inputs.items():
            token_values[tname] = site_token(site_key, tinput)

        # Track which token columns we have generated
        for t in token_values.keys():
            if t not in token_names:
                token_names.append(t)

        # 5. Store Result
        outrow = {"id": rid}
        outrow.update(token_values)
        outputs.append(outrow)

    # Write Output
    # Sort headers to ensure deterministic output column order
    token_names_sorted = sorted(token_names)
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=token_names_sorted)
        writer.writeheader()
        for r in outputs:
            # Filter the row to only include fields in the header
            # (Prevents errors if a row generated a token that others didn't, or vice versa)
            r = {k: v for k, v in r.items() if k in token_names_sorted}
            writer.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Generate Datavant-like tokens WITHOUT a master salt.")
    ap.add_argument("--in", dest="infile", required=True, help="Input CSV path")
    ap.add_argument("--out", dest="outfile", required=True, help="Output CSV path")
    ap.add_argument("--site-key", required=True, help="Site-specific key for AES encryption")
    ap.add_argument("--id-col", dest="idcol", default=None, help="Optional ID column (defaults to row index)")
    args = ap.parse_args()

    process_csv(args.infile, args.outfile, args.site_key, args.idcol)

if __name__ == "__main__":
    main()
