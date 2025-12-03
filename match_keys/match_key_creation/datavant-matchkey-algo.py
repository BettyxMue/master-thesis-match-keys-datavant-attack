#!/usr/bin/env python3
"""
Datavant-like Token Generation Script (HMAC Variant)
Master Thesis: Record Linkage with Match Key Algorithms - Is it secure?
Author: Babett Müller

Description:
    This script simulates the "Tokenization" phase of a Privacy-Preserving Record Linkage (PPRL)
    process, specifically modeling the Datavant architecture which uses a two-step encryption:
    1. Master Token Creation: HMAC-SHA256(MasterSalt, Normalized_PII)
    2. Site Token Creation: AES-ECB(SiteKey, MasterToken)

    This double-layer approach separates the "hashing" logic (Master Salt) from the 
    "site separation" logic (Site Key), allowing tokens to be transformed for linkage 
    without exposing the raw hash.

Usage:
    python3 datavant-matchkey-algo.py --in input.csv --out output.csv \
        --master-salt "YOUR_SALT" --site-key "YOUR_KEY"
"""

from jellyfish import soundex
import argparse
import base64
import csv
import hashlib
import hmac
import sys
from Crypto.Cipher import AES 
from datetime import datetime
from typing import Dict, Any, Optional, List

# ==============================================================================
# 1. NORMALIZATION UTILITIES
# ==============================================================================
# Standardizes PII to ensure consistent hashing across different data sources.

def norm_str(s: Optional[str]) -> str:
    """
    Removes non-alphanumeric characters and converts to lowercase.
    Example: "O'Connor" -> "oconnor"
    """
    if s is None:
        return ""
    return "".join(ch for ch in s.strip().lower() if ch.isalnum())

def norm_name(s: Optional[str]) -> str:
    """Wrapper for name normalization (currently alias for norm_str)."""
    return norm_str(s)

def first_initial(name: Optional[str]) -> str:
    """Extracts the first letter of the normalized name."""
    n = norm_name(name)
    return n[0] if n else ""

def first_n(name: Optional[str], n: int) -> str:
    """Extracts the first N letters of the normalized name."""
    nm = norm_name(name)
    return nm[:n] if nm else ""

def norm_sex(sx: Optional[str]) -> str:
    """
    Standardizes gender/sex to single character codes: 'm', 'f', or 'u'.
    """
    sx = (sx or "").strip().lower()
    if sx in ("m", "male"):
        return "m"
    if sx in ("f", "female"):
        return "f"
    return "u"  # unknown

def norm_dob(d: Optional[str]) -> str:
    """
    Standardizes dates to 'YYYYMMDD' string format.
    Handles various input formats (dashes, dots, slashes).
    """
    if not d or not str(d).strip():
        return ""
    s = str(d).strip()
    fmts = ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y%m%d")
    for f in fmts:
        try:
            dt = datetime.strptime(s, f)
            return dt.strftime("%Y%m%d")
        except ValueError:
            pass
    if len(s) == 8 and s.isdigit():
        return s
    return ""

def year_of_birth(d: Optional[str]) -> str:
    """Extracts 4-digit year from DOB."""
    ymd = norm_dob(d)
    return ymd[:4] if ymd else ""

def zip3(z: Optional[str]) -> str:
    """Extracts first 3 digits of ZIP code (HIPAA Safe Harbor)."""
    digits = "".join(ch for ch in str(z or "") if ch.isdigit())
    return digits[:3]

def norm_phone(p: Optional[str]) -> str:
    """Retains only digits from phone numbers."""
    return "".join(ch for ch in str(p or "") if ch.isdigit())

def norm_email(e: Optional[str]) -> str:
    """Lowercases and trims emails."""
    return (e or "").strip().lower()

def norm_address(a: Optional[str]) -> str:
    """Normalizes address string (alphanumeric only)."""
    return norm_str(a)


# ==============================================================================
# 2. CRYPTOGRAPHIC CORE
# ==============================================================================

def b64_44(raw: bytes) -> str:
    """
    Encodes binary data to Base64 string (ASCII).
    Typically results in 44 chars for 32-byte inputs including padding.
    """
    return base64.b64encode(raw).decode("ascii")

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Computes HMAC-SHA256.
    Used to generate the 'Master Token' from the salt and PII.
    """
    return hmac.new(key, data, hashlib.sha256).digest()

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """
    Encrypts data using AES in ECB mode.
    Validates key length (16/32 bytes) and data alignment.
    
    Note: SHA-256 output (32 bytes) is naturally aligned to AES block size (16 bytes).
    """
    if key is None or len(key) not in (16, 32):
        raise ValueError("Key must be 16 or 32 bytes (AES-128 or AES-256).")
    
    if len(data) % 16 != 0:
        raise ValueError("Plaintext length must be multiple of 16 bytes.")
        
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def make_master_token(master_salt: bytes, token_input: str) -> bytes:
    """
    Step 1: Master Token Creation.
    Combines the Master Salt and the concatenated PII string using HMAC.
    
    Output: 32 bytes (binary hash)
    """
    return hmac_sha256(master_salt, token_input.encode("utf-8"))

def make_site_token(master_token: bytes, site_key: bytes) -> str:
    """
    Step 2: Site Token Creation.
    Encrypts the Master Token with the Site Key to make it unique to the data owner.
    
    Output: Base64 string
    """
    site_digest = aes_ecb_encrypt(site_key, master_token)
    return b64_44(site_digest)


# ==============================================================================
# 3. TOKEN RECIPES
# ==============================================================================

def recipe_inputs(row: Dict[str, Any]) -> Dict[str, str]:
    """
    Extracts and normalizes all fields from a raw CSV row.
    Also computes derived features (Soundex, Initials).
    """
    # Basic Normalization
    fn = norm_name(row.get("first_name"))
    ln = norm_name(row.get("last_name"))
    dob = norm_dob(row.get("dob"))
    yob = year_of_birth(row.get("dob"))
    sx  = norm_sex(row.get("sex"))
    zp = zip3(row.get("zip"))
    ph = norm_phone(row.get("phone"))
    em = norm_email(row.get("email"))
    addr = norm_address(row.get("address"))

    # Derived Features
    fi = first_initial(row.get("first_name"))
    f3 = first_n(row.get("first_name"), 3)
    sdx_fn = soundex(row.get("first_name"))
    sdx_ln = soundex(row.get("last_name"))

    return dict(
        fn=fn, ln=ln, dob=dob, yob=yob, sx=sx, zp=zp, ph=ph, em=em, addr=addr,
        fi=fi, f3=f3, sdx_fn=sdx_fn, sdx_ln=sdx_ln
    )

def build_token_inputs(rowvars: Dict[str, str]) -> Dict[str, str]:
    """
    Constructs the raw input strings for each Token Type (Match Key).
    Only generates a token if all required components are present.
    
    Format: "Field1|Field2|..."
    """
    # Unpack for cleaner logic
    fn = rowvars["fn"]; ln = rowvars["ln"]; dob = rowvars["dob"]; sx = rowvars["sx"]
    zp = rowvars["zp"]; fi = rowvars["fi"]; f3 = rowvars["f3"]
    sdx_fn = rowvars["sdx_fn"]; sdx_ln = rowvars["sdx_ln"]
    ph = rowvars["ph"]; em = rowvars["em"]; addr = rowvars["addr"]; yob = rowvars["yob"]

    tokens: Dict[str, str] = {}

    # T1: LastName + FirstInitial + sex + DOB
    if ln and fi and sx and dob:
        tokens["T1"] = "|".join([ln, fi, sx, dob])

    # T2: Soundex(Last) + Soundex(First) + sex + DOB
    if sdx_ln and sdx_fn and sx and dob:
        tokens["T2"] = "|".join([sdx_ln, sdx_fn, sx, dob])

    # T3: Last + First + DOB + ZIP3
    if ln and fn and dob and zp:
        tokens["T3"] = "|".join([ln, fn, dob, zp])

    # T4: Last + First + sex + DOB
    if ln and fn and sx and dob:
        tokens["T4"] = "|".join([ln, fn, sx, dob])

    # T7: Last + First3 + sex + DOB
    if ln and f3 and sx and dob:
        tokens["T7"] = "|".join([ln, f3, sx, dob])

    # T9: First + Address (very fuzzy—supplemental only)
    if fn and addr:
        tokens["T9"] = "|".join([fn, addr])

    return tokens

# ==============================================================================
# 4. MAIN PROCESSING LOOP
# ==============================================================================

def process_csv(
    infile: str,
    outfile: str,
    master_salt: str,
    site_key: str,
    id_column: Optional[str] = None
):
    """
    Read CSV with columns:
      first_name,last_name,dob,sex,zip,address,phone,email
    Produce CSV with: id (or row_index), and token columns (T1, T2, ...)
    """
    # Keys are expected as hex or raw; accept either.
    try:
        master = bytes.fromhex(master_salt)
    except ValueError:
        master = master_salt.encode("utf-8")
    try:
        site = bytes.fromhex(site_key)
    except ValueError:
        site = site_key.encode("utf-8")

    # Open Input
    try:
        f_in = open(infile, newline="", encoding="utf-8")
        reader = csv.DictReader(f_in)
        rows = list(reader)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {infile}")

    # Gather all token names that appear
    token_names: List[str] = []
    outputs: List[Dict[str, str]] = []

    print(f"[*] Processing {len(rows)} records...")

    for i, row in enumerate(rows):
        # Determine Record ID
        rid = row.get(id_column) if id_column and id_column in row else str(i)

        # Normalize & Build Recipes
        vars_ = recipe_inputs(row)
        token_inputs = build_token_inputs(vars_)

        # Compute site-specific tokens
        token_values: Dict[str, str] = {}
        for tname, tinput in token_inputs.items():
            # Step 1: HMAC with Master Salt
            master_token = make_master_token(master, tinput)
            # Step 2: AES with Site Key
            site_token = make_site_token(master_token, site)
            token_values[tname] = site_token

        # Track all token names encountered
        for t in token_values.keys():
            if t not in token_names:
                token_names.append(t)

        outrow = {"id": rid}
        outrow.update(token_values)
        outputs.append(outrow)

    # Write output with stable token column order
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["id"] + token_names
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in outputs:
            writer.writerow(r)

def main():
    ap = argparse.ArgumentParser(
        description="Generate Datavant-like match tokens from PII."
    )
    ap.add_argument("--in", dest="infile", required=True, help="Input CSV path")
    ap.add_argument("--out", dest="outfile", required=True, help="Output CSV path")
    ap.add_argument(
        "--master-salt",
        required=True,
        help="Master salt/pepper (hex or string) for HMAC over token inputs",
    )
    ap.add_argument(
        "--site-key",
        required=True,
        help="Site-specific key (hex or string) for HMAC over master token",
    )
    ap.add_argument(
        "--id-col",
        dest="idcol",
        default=None,
        help="Optional ID column name; defaults to row index if omitted",
    )
    args = ap.parse_args()
    try:
        process_csv(args.infile, args.outfile, args.master_salt, args.site_key, args.idcol)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

"""
python datavant_like_tokens.py \
  --in patients.csv \
  --out tokens.csv \
  --master-salt "c0ffee_cafe_master_salt" \
  --site-key "deadbeef_deadbeef_site_key" \
  --id-col id
"""