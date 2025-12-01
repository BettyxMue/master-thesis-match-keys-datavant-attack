#!/usr/bin/env python3
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

############################
# Normalization utilities
############################

def norm_str(s: Optional[str]) -> str:
    if s is None:
        return ""
    return "".join(ch for ch in s.strip().lower() if ch.isalnum())

def norm_name(s: Optional[str]) -> str:
    return norm_str(s)

def first_initial(name: Optional[str]) -> str:
    n = norm_name(name)
    return n[0] if n else ""

def first_n(name: Optional[str], n: int) -> str:
    nm = norm_name(name)
    return nm[:n] if nm else ""

""" def soundex(name: Optional[str]) -> str:
    # Classic Soundex (English). Good enough for experiments.
    n = norm_name(name)
    if not n:
        return ""
    first = n[0].upper()
    map_tbl = {
        "bfpv": "1",
        "cgjkqsxz": "2",
        "dt": "3",
        "l": "4",
        "mn": "5",
        "r": "6",
    }
    def code(ch):
        for k, v in map_tbl.items():
            if ch in k:
                return v
        return ""
    digits = []
    prev = ""
    for ch in n[1:]:
        c = code(ch)
        if c and c != prev:
            digits.append(c)
        prev = c
    sd = (first + "".join(digits) + "000")[:4]
    return sd """

def norm_sex(sx: Optional[str]) -> str:
    sx = (sx or "").strip().lower()
    if sx in ("m", "male"):
        return "m"
    if sx in ("f", "female"):
        return "f"
    return "u"  # unknown

def norm_dob(d: Optional[str]) -> str:
    """Return YYYYMMDD or '' if invalid."""
    if not d or not str(d).strip():
        return ""
    s = str(d).strip()
    # Try a few common formats
    fmts = ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y%m%d")
    for f in fmts:
        try:
            dt = datetime.strptime(s, f)
            return dt.strftime("%Y%m%d")
        except ValueError:
            pass
    # If already looks like YYYYMMDD
    if len(s) == 8 and s.isdigit():
        return s
    return ""

def year_of_birth(d: Optional[str]) -> str:
    ymd = norm_dob(d)
    return ymd[:4] if ymd else ""

def zip3(z: Optional[str]) -> str:
    digits = "".join(ch for ch in str(z or "") if ch.isdigit())
    return digits[:3]

def norm_phone(p: Optional[str]) -> str:
    return "".join(ch for ch in str(p or "") if ch.isdigit())

def norm_email(e: Optional[str]) -> str:
    # Minimal normalization; emails are case-insensitive in the local-part for most link use-cases
    return (e or "").strip().lower()

def norm_address(a: Optional[str]) -> str:
    # Light normalization; proper address standardization is complex
    return norm_str(a)

############################
# Crypto utilities
############################

def b64_44(raw: bytes) -> str:
    """Return base64 string typically 44 chars with '==' padding (URL-safe optional)."""
    return base64.b64encode(raw).decode("ascii")

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def make_site_token(master_token: bytes, site_key: bytes) -> str:
    """Site-specific AES over master token"""
    site_digest = aes_ecb_encrypt(site_key, master_token)
    return b64_44(site_digest)

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
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

def make_master_token(master_salt: bytes, token_input: str) -> bytes:
    """HMAC-SHA256(salt, normalized_input) → 32-byte master token"""
    return hmac_sha256(master_salt, token_input.encode("utf-8"))

############################
# Token recipe definitions
############################

def recipe_inputs(row: Dict[str, Any]) -> Dict[str, str]:
    # Normalize once; reuse
    fn = norm_name(row.get("first_name"))
    ln = norm_name(row.get("last_name"))
    dob = norm_dob(row.get("dob"))
    yob = year_of_birth(row.get("dob"))
    sx  = norm_sex(row.get("sex"))
    zp = zip3(row.get("zip"))
    ph = norm_phone(row.get("phone"))
    em = norm_email(row.get("email"))
    addr = norm_address(row.get("address"))

    # Precomputed variants
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
    Define Datavant-like token recipes (no SSN by default).
    You can toggle/add recipes as needed.
    Each token input is a single string; fields concatenated with a clear delimiter
    before hashing (delimiters are fine since we HMAC the full string).
    """
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

    # T5: SSN

    # T7: Last + First3 + sex + DOB
    if ln and f3 and sx and dob:
        tokens["T7"] = "|".join([ln, f3, sx, dob])

    # T9: First + Address (very fuzzy—supplemental only)
    if fn and addr:
        tokens["T9"] = "|".join([fn, addr])

    # T16: SSN + First

    # T22: Phone
    if ph:
        tokens["T22"] = ph

    # T40: 

    """# (Optional) Email-based token
    if em:
        tokens["TEMAIL"] = em

    # (Optional) Name + YOB (weaker)
    if ln and fn and yob:
        tokens["TNAMEYOB"] = "|".join([ln, fn, yob])"""

    return tokens

############################
# Main processing
############################

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

    reader = csv.DictReader(open(infile, newline="", encoding="utf-8"))
    rows = list(reader)

    # Gather all token names that appear
    token_names: List[str] = []
    outputs: List[Dict[str, str]] = []

    for i, row in enumerate(rows):
        rid = row.get(id_column) if id_column and id_column in row else str(i)
        vars_ = recipe_inputs(row)
        token_inputs = build_token_inputs(vars_)

        # Compute site-specific tokens
        token_values: Dict[str, str] = {}
        for tname, tinput in token_inputs.items():
            master_token = make_master_token(master, tinput)
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