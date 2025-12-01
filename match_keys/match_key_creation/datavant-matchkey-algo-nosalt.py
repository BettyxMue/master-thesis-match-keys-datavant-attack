#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from jellyfish import soundex
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

############################
# Normalization utilities
############################

def norm_str(s: Optional[str]) -> str:
    if s is None:
        return ""
    return "".join(ch for ch in s.strip().lower() if ch.isalnum())

def norm_name(s: Optional[str]) -> str:
    return norm_str(s).strip().lower()

def first_initial(name: Optional[str]) -> str:
    n = norm_name(name).strip().lower()
    return n[0] if n else ""

def first_n(name: Optional[str], n: int) -> str:
    nm = norm_name(name).strip().lower()
    return nm[:n] if nm else ""

def norm_sex(sx: Optional[str]) -> str:
    sx = (sx or "").strip().lower()
    if sx in ("m", "male"): return "m"
    if sx in ("f", "female"): return "f"
    return "u"

def norm_dob(d: Optional[str]) -> str:
    if not d or not str(d).strip():
        return ""
    s = str(d).strip()
    fmts = ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y%m%d")
    for f in fmts:
        try:
            return datetime.strptime(s, f).strftime("%Y%m%d")
        except ValueError:
            pass
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
    return (e or "").strip().lower()

def norm_address(a: Optional[str]) -> str:
    return norm_str(a).strip().lower()

############################
# Crypto (no master salt)
############################

def parse_aes128_256_key(s: str) -> bytes:
    """Accept hex or utf-8; must be exactly 32 bytes for AES-256."""
    try:
        key = bytes.fromhex(s)
    except ValueError:
        key = s.encode("utf-8")
    if len(key) != 32 and len(key) != 16:
        raise ValueError(f"Site key must be 16 or 32 bytes for AES-128/256; got {len(key)} bytes")
    return key

def master_sha256(token_input: str) -> bytes:
    """Master token (32 bytes) = SHA-256 over the normalized token input string."""
    return hashlib.sha256(token_input.encode("utf-8")).digest()

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

def site_token(site_key: bytes, token_input: str) -> str:
    """Compute site token = Base64( AES-128/256-ECB( SHA-256(token_input) ) )."""
    master = master_sha256(token_input)
    ct = aes_ecb_encrypt(site_key, master)
    return base64.b64encode(ct).decode("ascii")

############################
# Token recipe definitions
############################

def recipe_inputs(row: Dict[str, Any]) -> Dict[str, str]:
    fn = norm_name(row.get("first_name"))
    ln = norm_name(row.get("last_name"))
    dob = norm_dob(row.get("dob"))
    yob = year_of_birth(row.get("dob"))
    sx  = norm_sex(row.get("sex"))
    zp = zip3(row.get("zip"))
    ph = norm_phone(row.get("phone"))
    em = norm_email(row.get("email"))
    addr = norm_address(row.get("address"))

    fi = first_initial(row.get("first_name"))
    f3 = first_n(row.get("first_name"), 3)
    sdx_fn = soundex(row.get("first_name"))
    sdx_ln = soundex(row.get("last_name"))

    return dict(
        fn=fn, ln=ln, dob=dob, yob=yob, sx=sx, zp=zp, ph=ph, em=em, addr=addr,
        fi=fi, f3=f3, sdx_fn=sdx_fn, sdx_ln=sdx_ln
    )

def build_token_inputs(v: Dict[str, str]) -> Dict[str, str]:
    fn, ln, dob, sx, zp = v["fn"], v["ln"], v["dob"], v["sx"], v["zp"]
    fi, f3, sdx_fn, sdx_ln = v["fi"], v["f3"], v["sdx_fn"], v["sdx_ln"]
    ph, em, addr, yob = v["ph"], v["em"], v["addr"], v["yob"]

    tokens: Dict[str, str] = {}

    # T1: Last + FirstInitial + sex + DOB
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

    # T22: Phone (US) # leave out?
    """if ph:
        tokens["T22"] = ph"""

    # T40: Last + First + DOB + State # leave out?
    """ if ln and fn and dob and state:
        tokens["T40"] = "|".join([ln, fn, dob, state]) """ 

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

def process_csv(infile: str, outfile: str, site_key_str: str, id_column: Optional[str] = None):
    site_key = parse_aes128_256_key(site_key_str)

    with open(infile, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    token_names: List[str] = []
    outputs: List[Dict[str, str]] = []

    for i, row in enumerate(rows):
        rid = row.get(id_column) if id_column and id_column in row else str(i)
        v = recipe_inputs(row)
        token_inputs = build_token_inputs(v)

        token_values: Dict[str, str] = {}
        for tname, tinput in token_inputs.items():
            token_values[tname] = site_token(site_key, tinput)

        for t in token_values.keys():
            if t not in token_names:
                token_names.append(t)

        outrow = {"id": rid}
        outrow.update(token_values)
        outputs.append(outrow)

    # Write only token columns (no id) in a stable order
    token_names_sorted = sorted(token_names)
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=token_names_sorted)
        writer.writeheader()
        for r in outputs:
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
